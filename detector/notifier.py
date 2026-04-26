"""
notifier.py — Slack webhook notification sender.

All alerts fire within 10 seconds of detection because the monitor
calls this synchronously in the processing loop. Network calls are
wrapped in a timeout to prevent blocking the monitor thread.

Each alert type includes: condition fired, current rate, baseline,
timestamp, and (where applicable) ban duration.
"""

import time
import threading
import logging
import requests

logger = logging.getLogger("notifier")


class SlackNotifier:
    def __init__(self, config):
        self.webhook_url: str = config["slack"]["webhook_url"]
        # Fire-and-forget: send in a daemon thread so monitor loop isn't blocked
        self._pool_lock = threading.Lock()

    #  Public alert methods                                               

    def send_ban_alert(
        self,
        ip: str,
        condition: str,
        rate: float,
        duration: int,
        baseline_mean: float,
    ) -> None:
        dur_str = f"{duration}s" if duration > 0 else "🔒 *PERMANENT*"
        text = (
            f"🚫 *IP BANNED*\n"
            f"*IP:* `{ip}`\n"
            f"*Condition:* {condition}\n"
            f"*Current Rate:* `{rate:.2f} req/s`\n"
            f"*Baseline Mean:* `{baseline_mean:.2f} req/s`\n"
            f"*Ban Duration:* {dur_str}\n"
            f"*Timestamp:* `{self._now()}`"
        )
        self._fire(text)

    def send_unban_alert(
        self,
        ip: str,
        previous_level: int,
        is_permanent_next: bool,
    ) -> None:
        next_str = (
            "⚠️ Next offence will be *permanent*"
            if is_permanent_next
            else f"Next offence → level {previous_level + 1}"
        )
        text = (
            f"✅ *IP UNBANNED*\n"
            f"*IP:* `{ip}`\n"
            f"*Released from Level:* {previous_level}\n"
            f"*Status:* {next_str}\n"
            f"*Timestamp:* `{self._now()}`"
        )
        self._fire(text)

    def send_global_alert(
        self,
        condition: str,
        global_rps: float,
        baseline_mean: float = 0.0,
    ) -> None:
        text = (
            f"⚠️ *GLOBAL TRAFFIC ANOMALY — NO BLOCK*\n"
            f"*Condition:* {condition}\n"
            f"*Global Rate:* `{global_rps:.2f} req/s`\n"
            f"*Baseline Mean:* `{baseline_mean:.2f} req/s`\n"
            f"*Timestamp:* `{self._now()}`\n"
            f"_No single IP crosses the per-IP threshold. "
            f"Monitor for coordinated attack patterns._"
        )
        self._fire(text)

    #  Internal                                                           

    def _fire(self, text: str) -> None:
        """Send in a background daemon thread to avoid blocking the monitor."""
        t = threading.Thread(target=self._post, args=(text,), daemon=True)
        t.start()

    def _post(self, text: str) -> None:
        try:
            resp = requests.post(
                self.webhook_url,
                json={"text": text},
                timeout=8,
            )
            if resp.status_code != 200:
                logger.warning(
                    f"Slack returned {resp.status_code}: {resp.text[:200]}"
                )
        except requests.exceptions.RequestException as e:
            logger.error(f"Slack webhook failed: {e}")

    @staticmethod
    def _now() -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
