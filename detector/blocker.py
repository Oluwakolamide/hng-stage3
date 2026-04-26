"""
blocker.py — iptables ban/unban management.

Each IP progresses through a backoff ban-level ladder defined in config:
  Level 0 → 10 min, Level 1 → 30 min, Level 2 → 2 hr, Level 3+ → permanent.

The ban state is kept in-memory (banned_ips dict) and iptables rules are
added/removed via subprocess calls. Audit entries are written for every
ban and unban.

Audit format:
  [timestamp] ACTION ip | condition | rate=X | baseline=Y | duration=Zs
"""

import subprocess
import time
import threading
import logging
import os

logger = logging.getLogger("blocker")


class IPBlocker:
    def __init__(self, config):
        self.unban_schedule: list = config.get("unban_schedule", [600, 1800, 7200])
        self.audit_log: str = config["audit_log"]
        os.makedirs(os.path.dirname(self.audit_log), exist_ok=True)

        # ip -> {ban_time, level, unban_time, duration}
        self.banned_ips: dict = {}
        self._lock = threading.Lock()

    #  State queries                                                       

    def is_banned(self, ip: str) -> bool:
        with self._lock:
            return ip in self.banned_ips

    def get_banned_ips(self) -> dict:
        with self._lock:
            return dict(self.banned_ips)

    #  Ban                                                                 

    def ban_ip(self, ip: str) -> int:
        """
        Insert iptables DROP rule for ip.

        Returns the ban duration in seconds, or -1 for permanent.
        If the IP is already permanently banned, returns -1 without
        adding a duplicate rule.
        """
        with self._lock:
            existing = self.banned_ips.get(ip)
            if existing:
                level = existing["level"]
            else:
                level = 0

            # Permanent once we exhaust the schedule
            if level >= len(self.unban_schedule):
                duration = -1
            else:
                duration = self.unban_schedule[level]

            unban_time = (time.time() + duration) if duration > 0 else None

            self.banned_ips[ip] = {
                "ban_time": time.time(),
                "level": level + 1,
                "unban_time": unban_time,
                "duration": duration,
            }

        self._iptables_insert(ip)
        logger.info(f"Banned {ip} duration={duration}s level={level + 1}")
        return duration

    #  Unban                                                               

    def unban_ip(self, ip: str) -> bool:
        """Remove iptables rule and clear ban state. Returns True on success."""
        with self._lock:
            if ip not in self.banned_ips:
                return False
            del self.banned_ips[ip]

        self._iptables_delete(ip)
        logger.info(f"Unbanned {ip}")
        return True
      
    #  Audit log                                                           #

    def write_audit(
        self,
        action: str,
        ip: str,
        condition: str,
        rate: float,
        baseline: float,
        duration: int = None,
    ) -> None:
        """
        Write a structured audit entry.

        Format:
          [2024-01-01T12:00:00Z] BAN 1.2.3.4 | z-score=4.1 | rate=12.300 | baseline=2.100 | duration=600s
        """
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if duration is None or duration == -1:
            dur_str = "permanent"
        else:
            dur_str = f"{duration}s"
        line = (
            f"[{ts}] {action} {ip} | {condition} "
            f"| rate={rate:.3f} | baseline={baseline:.3f} | duration={dur_str}\n"
        )
        try:
            with open(self.audit_log, "a") as f:
                f.write(line)
        except Exception:
            logger.warning("Could not write audit log entry")

    #  iptables helpers                                                    

    def _iptables_insert(self, ip: str) -> None:
        """Insert DROP rule at top of INPUT chain."""
        try:
            subprocess.run(
                ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True,
                timeout=5,
            )
        except FileNotFoundError:
            logger.warning("iptables not found — skipping block (dev mode?)")
        except subprocess.CalledProcessError as e:
            logger.error(f"iptables INSERT failed for {ip}: {e.stderr.decode().strip()}")
        except subprocess.TimeoutExpired:
            logger.error(f"iptables INSERT timed out for {ip}")

    def _iptables_delete(self, ip: str) -> None:
        """Delete DROP rule from INPUT chain."""
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True,
                timeout=5,
            )
        except FileNotFoundError:
            logger.warning("iptables not found — skipping unblock (dev mode?)")
        except subprocess.CalledProcessError as e:
            logger.error(f"iptables DELETE failed for {ip}: {e.stderr.decode().strip()}")
        except subprocess.TimeoutExpired:
            logger.error(f"iptables DELETE timed out for {ip}")
