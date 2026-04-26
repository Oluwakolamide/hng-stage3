"""
unbanner.py — Automatic IP unban scheduler with backoff.

When an IP is banned, monitor.py calls schedule_unban(ip).
This module maintains a queue of (ip, scheduled_unban_time) pairs
and checks them every 5 seconds in a background thread.

Backoff ladder (from config.yaml):
  Strike 1 → ban 10 min  → auto-unban → re-offend → strike 2
  Strike 2 → ban 30 min  → auto-unban → re-offend → strike 3
  Strike 3 → ban 2 hr    → auto-unban → re-offend → strike 4
  Strike 4+ → permanent (no auto-unban)

A Slack notification is sent on every unban event.
An audit entry is written for each unban.
"""

import time
import threading
import logging

logger = logging.getLogger("unbanner")


class AutoUnbanner:
    def __init__(self, config, blocker, notifier):
        self.blocker = blocker
        self.notifier = notifier
        self.unban_schedule: list = config.get("unban_schedule", [600, 1800, 7200])
        self.audit_log: str = config["audit_log"]

        # ip -> scheduled_unban_time (unix timestamp)
        self._pending: dict = {}
        self._lock = threading.Lock()

    def schedule_unban(self, ip: str) -> None:
        """
        Queue an IP for auto-unban based on its current ban level.
        Called immediately after ban_ip so the timer starts from ban time.
        """
        banned = self.blocker.get_banned_ips()
        info = banned.get(ip)
        if not info:
            return

        duration = info.get("duration", -1)
        if duration == -1:
            # Permanent — nothing to schedule
            logger.info(f"{ip} is permanently banned, no auto-unban scheduled")
            return

        unban_at = time.time() + duration
        with self._lock:
            self._pending[ip] = unban_at

        logger.info(f"Scheduled unban for {ip} in {duration}s")

    def run(self) -> None:
        """Background thread — polls the pending queue every 5 seconds."""
        while True:
            now = time.time()
            due = []

            with self._lock:
                for ip, unban_at in list(self._pending.items()):
                    if now >= unban_at:
                        due.append(ip)
                        del self._pending[ip]

            for ip in due:
                self._do_unban(ip)

            time.sleep(5)

    #  Internal                                                           

    def _do_unban(self, ip: str) -> None:
        """Unban an IP, write audit log, send Slack alert."""
        # Snapshot ban info before removing it
        banned = self.blocker.get_banned_ips()
        info = banned.get(ip, {})
        level = info.get("level", 1)

        success = self.blocker.unban_ip(ip)
        if not success:
            logger.warning(f"Could not unban {ip} — may have already been removed")
            return

        is_permanent_next = level >= len(self.unban_schedule)

        # Audit
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        line = (
            f"[{ts}] UNBAN {ip} | auto-release after level {level} ban"
            f" | rate=n/a | baseline=n/a"
            f" | next={'permanent' if is_permanent_next else self.unban_schedule[level] if level < len(self.unban_schedule) else 'permanent'}\n"
        )
        try:
            with open(self.audit_log, "a") as f:
                f.write(line)
        except Exception:
            logger.warning("Could not write unban audit entry")

        # Slack
        try:
            self.notifier.send_unban_alert(ip, level, is_permanent_next)
        except Exception:
            logger.exception(f"Slack unban alert failed for {ip}")

        logger.info(f"Auto-unbanned {ip} (was level {level})")
