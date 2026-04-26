"""
monitor.py — Nginx access log tail and sliding-window tracker.

Two deque-based sliding windows are maintained:
  • ip_windows[ip]      — timestamps of requests from that IP in last 60s
  • global_window       — timestamps of ALL requests in last 60s

Eviction logic:
  On every incoming log line, before appending the new timestamp,
  we pop from the LEFT of each deque while:
      now - deque[0] > window_seconds

  Because timestamps are appended in (approximate) order, the left end
  is always the oldest, making popleft() O(1). The current rate is
  simply len(window) / window_seconds — no division quirks needed.

Each parsed log line is dispatched to:
  - baseline.record_request()   → updates per-second counts
  - detector.check_ip()         → may trigger ban
  - detector.check_global()     → may trigger Slack-only alert

The monitor also maintains ip_counts (total requests per IP) and
exposes get_top_ips() / get_global_rps() for the dashboard.
"""

import os
import time
import json
import logging
import threading
from collections import deque, defaultdict

logger = logging.getLogger("monitor")


class LogMonitor:
    def __init__(self, config, baseline, detector, blocker, notifier, unbanner):
        self.config = config
        self.baseline = baseline
        self.detector = detector
        self.blocker = blocker
        self.notifier = notifier
        self.unbanner = unbanner

        self.log_path: str = config["nginx"]["log_path"]
        self.window_seconds: int = config["detection"]["window_seconds"]  # 60

        # --- Sliding windows ---
        # ip_windows: IP → deque of float timestamps (last window_seconds seconds)
        # global_window: deque of float timestamps (last window_seconds seconds)
        # ip_error_windows: IP → deque of float timestamps for 4xx/5xx requests
        self.ip_windows: dict = defaultdict(deque)
        self.global_window: deque = deque()
        self.ip_error_windows: dict = defaultdict(deque)

        # --- Dashboard stats ---
        self.total_requests: int = 0
        self.start_time: float = time.time()
        self.last_line: str = ""

        self._lock = threading.Lock()

        # --- Global alert dedup ---
        self._last_global_alert_condition: str = ""

    # ------------------------------------------------------------------ #
    #  Public API (called by dashboard)                                   #
    # ------------------------------------------------------------------ #

    def get_global_rps(self) -> float:
        now = time.time()
        with self._lock:
            self._evict(self.global_window, now)
            return len(self.global_window) / self.window_seconds

    def get_ip_rps(self, ip: str) -> float:
        now = time.time()
        with self._lock:
            self._evict(self.ip_windows[ip], now)
            return len(self.ip_windows[ip]) / self.window_seconds

    def get_top_ips(self, n: int = 10) -> list:
        """Return [(ip, rps), ...] sorted by descending rps, top-n."""
        now = time.time()
        rates = {}
        with self._lock:
            for ip, window in list(self.ip_windows.items()):
                self._evict(window, now)
                rates[ip] = len(window) / self.window_seconds
        return sorted(rates.items(), key=lambda x: x[1], reverse=True)[:n]

    # ------------------------------------------------------------------ #
    #  Log processing                                                      #
    # ------------------------------------------------------------------ #

    def process_line(self, line: str) -> None:
        line = line.strip()
        if not line:
            return

        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return

        # Extract fields from the JSON log entry
        ip = self._extract_ip(entry)
        if not ip or ip == "-":
            return

        try:
            status = int(entry.get("status", 200))
        except (ValueError, TypeError):
            status = 200

        is_error = status >= 400
        now = time.time()

        # --- Update sliding windows and baseline (under lock) ---
        with self._lock:
            # Evict stale entries from global and per-IP windows
            self._evict(self.global_window, now)
            self._evict(self.ip_windows[ip], now)
            self._evict(self.ip_error_windows[ip], now)

            # Append current timestamp
            self.global_window.append(now)
            self.ip_windows[ip].append(now)
            if is_error:
                self.ip_error_windows[ip].append(now)

            # Snapshot rates while we still hold the lock
            global_rps = len(self.global_window) / self.window_seconds
            ip_rps = len(self.ip_windows[ip]) / self.window_seconds
            ip_error_rps = len(self.ip_error_windows[ip]) / self.window_seconds

            self.total_requests += 1
            self.last_line = line

        # Record to baseline (has its own lock)
        self.baseline.record_request(now, is_error=is_error)

        # --- Anomaly detection (no lock — detector/blocker have their own) ---
        if self.blocker.is_banned(ip):
            return

        # Per-IP check
        ip_anomalous, ip_condition = self.detector.check_ip(ip, ip_rps, ip_error_rps)
        if ip_anomalous:
            mean, _, _, _ = self.baseline.get_stats()
            duration = self.blocker.ban_ip(ip)
            self.blocker.write_audit("BAN", ip, ip_condition, ip_rps, mean, duration)
            self.notifier.send_ban_alert(ip, ip_condition, ip_rps, duration, mean)
            self.unbanner.schedule_unban(ip)

        # Global check (alert only)
        global_anomalous, global_condition = self.detector.check_global(global_rps)
        if global_anomalous:
            mean, _, _, _ = self.baseline.get_stats()
            self.notifier.send_global_alert(global_condition, global_rps, mean)

    # ------------------------------------------------------------------ #
    #  Log tail                                                            #
    # ------------------------------------------------------------------ #

    def run(self) -> None:
        """
        Tail the Nginx access log line by line, indefinitely.

        Strategy:
          - Wait for the file to appear (Nginx may not have written yet).
          - Seek to end of file on first open (we only care about new traffic).
          - On EOF, sleep briefly and retry readline() — classic tail -f pattern.
          - If the file disappears (logrotate), reopen it.
        """
        logger.info(f"Waiting for log file: {self.log_path}")
        while not os.path.exists(self.log_path):
            time.sleep(2)

        logger.info(f"Tailing log: {self.log_path}")

        while True:
            try:
                with open(self.log_path, "r") as fh:
                    # Start from the current end — don't replay history
                    fh.seek(0, 2)
                    logger.info("Log monitor active — listening for requests")

                    while True:
                        line = fh.readline()
                        if not line:
                            # No new data yet — yield CPU briefly
                            time.sleep(0.05)
                            # Check if file was rotated (inode changed)
                            if not os.path.exists(self.log_path):
                                logger.warning("Log file removed — will reopen")
                                break
                            continue
                        self.process_line(line)

            except (OSError, IOError) as e:
                logger.error(f"Log file error: {e} — retrying in 2s")
                time.sleep(2)

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    def _evict(self, window: deque, now: float) -> None:
        """
        Pop entries from the LEFT of the deque while they are older than
        window_seconds.

        Since we always append timestamps in increasing order, popleft()
        correctly evicts the oldest entries first in O(1) per eviction.
        """
        while window and now - window[0] > self.window_seconds:
            window.popleft()

    @staticmethod
    def _extract_ip(entry: dict) -> str:
        """
        Pull source IP from the JSON log entry.

        Handles X-Forwarded-For chains like "203.0.113.5, 10.0.0.1"
        by taking the first (client-most) address.
        """
        raw = entry.get("source_ip") or entry.get("remote_addr", "")
        if not raw or raw == "-":
            return ""
        # XFF may be a comma-separated list; take leftmost (real client)
        return raw.split(",")[0].strip()
