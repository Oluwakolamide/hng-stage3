"""
baseline.py — Rolling baseline tracker.

Maintains a 30-minute sliding window of per-second request counts,
recalculated every 60 seconds. Per-hour slots are also maintained;
when the current hour has enough data, it takes priority over the
global rolling window. This means the baseline automatically adapts
to time-of-day traffic patterns.

Data structure:
  second_counts: deque of (unix_second, count) pairs, max 1800 entries.
  hour_slots: dict mapping hour (0–23) to list of per-second counts.

The effective_mean and effective_stddev are updated on each recalculation
and read by the detector and dashboard without recomputing.
"""

import time
import math
import threading
import logging
from collections import deque, defaultdict

logger = logging.getLogger("baseline")


class BaselineTracker:
    def __init__(self, config):
        self.window_secs = config["detection"]["baseline_window_minutes"] * 60  # 1800
        self.recalc_interval = config["detection"]["baseline_recalc_interval"]  # 60
        self.floor_rps = config["detection"]["floor_rps"]                        # 1.0
        self.min_hour_samples = config["detection"]["min_hour_samples"]          # 120
        self.audit_log = config["audit_log"]

        # --- Per-second rolling window ---
        # Each entry: (unix_second_int, request_count)
        # We append when a second boundary is crossed and evict from the left
        # when the oldest entry is older than baseline_window_secs.
        self.second_counts: deque = deque()         # (second, count)
        self.error_second_counts: deque = deque()   # (second, error_count)

        # Current second accumulator
        self.current_second: int = 0
        self.current_count: int = 0
        self.current_error_count: int = 0

        # --- Per-hour slots ---
        # Maps hour (0–23) -> list of per-second counts for that hour
        # Accumulated across all days while the daemon is running.
        self.hour_slots: dict = defaultdict(list)

        # --- Published baseline stats (read by detector/dashboard) ---
        self.effective_mean: float = self.floor_rps
        self.effective_stddev: float = 1.0
        self.error_mean: float = 0.05
        self.error_stddev: float = 0.05

        # History for the baseline graph (list of dicts)
        self.baseline_history: list = []

        self._lock = threading.Lock()

    #  Public API                                              

    def record_request(self, now: float, is_error: bool = False) -> None:
        """Called by the monitor for every parsed log line."""
        second = int(now)
        with self._lock:
            if second != self.current_second:
                # Crossed a second boundary — flush previous second.
                # Use _flush_second_locked() here (NOT _flush_second()) because
                # we already hold _lock; threading.Lock is non-reentrant.
                if self.current_second > 0:
                    self._flush_second_locked()
                self.current_second = second
                self.current_count = 0
                self.current_error_count = 0
            self.current_count += 1
            if is_error:
                self.current_error_count += 1

    def get_stats(self) -> tuple:
        """Return (mean, stddev, error_mean, error_stddev) — never blocks long."""
        with self._lock:
            return (
                self.effective_mean,
                self.effective_stddev,
                self.error_mean,
                self.error_stddev,
            )

    def get_history(self) -> list:
        with self._lock:
            return list(self.baseline_history)

    def recalculate(self) -> tuple:
        """
        Recompute mean and stddev from available data.

        Priority:
          1. Current hour's slot if it has >= min_hour_samples entries.
          2. Otherwise, the full rolling 30-min window.

        Writes an audit log entry on each recalculation.
        Returns (mean, stddev).
        """
        with self._lock:
            # Flush the in-progress second before computing
            if self.current_second > 0:
                self._flush_second_locked()

            now = time.time()
            current_hour = time.localtime(now).tm_hour

            hour_data = self.hour_slots.get(current_hour, [])

            if len(hour_data) >= self.min_hour_samples:
                # Prefer current-hour data — it captures time-of-day patterns
                counts = hour_data[-(self.window_secs):]
                source = "hour"
            else:
                # Fall back to full rolling window
                counts = [c for _, c in self.second_counts]
                source = "rolling"

            mean, stddev = self._compute_stats(counts)
            self.effective_mean = mean
            self.effective_stddev = stddev

            # Error baseline
            err_counts = [c for _, c in self.error_second_counts]
            err_mean, err_stddev = self._compute_stats(err_counts, floor=0.01)
            self.error_mean = err_mean
            self.error_stddev = err_stddev

            snap = {
                "timestamp": now,
                "mean": mean,
                "stddev": stddev,
                "samples": len(counts),
                "hour": current_hour,
                "source": source,
            }
            self.baseline_history.append(snap)
            if len(self.baseline_history) > 200:
                self.baseline_history = self.baseline_history[-200:]

        # Audit log (outside lock)
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        line = (
            f"[{ts}] BASELINE_RECALC * | source={source} hour={current_hour}"
            f" | mean={mean:.4f} | stddev={stddev:.4f}"
            f" | samples={len(counts)}\n"
        )
        self._write_audit(line)
        logger.info(line.strip())

        return mean, stddev

    def recalculate_loop(self) -> None:
        """Background thread — recalculates baseline every recalc_interval seconds."""
        # Give the monitor a head-start to collect initial traffic data
        time.sleep(self.recalc_interval)
        while True:
            try:
                self.recalculate()
            except Exception:
                logger.exception("Baseline recalculation failed")
            time.sleep(self.recalc_interval)
          
    #  Private helpers                                                    

    def _flush_second(self) -> None:
        """Lock must NOT be held when calling this."""
        with self._lock:
            self._flush_second_locked()

    def _flush_second_locked(self) -> None:
        """Lock MUST be held by caller."""
        s = self.current_second
        count = self.current_count
        err = self.current_error_count

        self.second_counts.append((s, count))
        self.error_second_counts.append((s, err))

        # Track per-hour slot
        hour = time.localtime(s).tm_hour
        self.hour_slots[hour].append(count)

        # Evict entries older than the rolling window
        cutoff = s - self.window_secs
        while self.second_counts and self.second_counts[0][0] < cutoff:
            self.second_counts.popleft()
        while self.error_second_counts and self.error_second_counts[0][0] < cutoff:
            self.error_second_counts.popleft()

    def _compute_stats(self, counts: list, floor: float = None) -> tuple:
        """Return (mean, stddev) from a list of counts."""
        effective_floor = floor if floor is not None else self.floor_rps
        if not counts:
            return effective_floor, 1.0

        mean = sum(counts) / len(counts)
        mean = max(mean, effective_floor)

        if len(counts) < 2:
            return mean, 1.0

        variance = sum((x - mean) ** 2 for x in counts) / (len(counts) - 1)
        stddev = max(math.sqrt(variance), 0.01)
        return mean, stddev

    def _write_audit(self, line: str) -> None:
        try:
            with open(self.audit_log, "a") as f:
                f.write(line)
        except Exception:
            logger.warning("Could not write audit log")
