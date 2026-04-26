"""
detector.py — Anomaly detection logic.

Two triggers fire independently — whichever trips first wins:
  1. Z-score  > zscore_threshold (default 3.0)
  2. Rate     > rate_multiplier × baseline mean (default 5×)

Error-surge shortcircuit:
  If an IP's 4xx/5xx rate is >= error_rate_multiplier × error baseline mean,
  we tighten both thresholds (halve them, with a floor) before checking.
  This catches scanners that generate lots of 404s even at lower req/s.

Global checks use the same triggers but result in a Slack-only alert —
no iptables block — with a cooldown to avoid flooding.
"""

import time
import threading
import logging

logger = logging.getLogger("detector")


class AnomalyDetector:
    def __init__(self, config, baseline):
        self.baseline = baseline
        self.zscore_threshold: float = config["detection"]["zscore_threshold"]
        self.rate_multiplier: float = config["detection"]["rate_multiplier"]
        self.error_rate_multiplier: float = config["detection"]["error_rate_multiplier"]
        self.global_alert_cooldown: float = config["detection"].get(
            "global_alert_cooldown", 60
        )

        self._last_global_alert: float = 0.0
        self._lock = threading.Lock()

    #  Per-IP check                                                        

    def check_ip(self, ip: str, ip_rps: float, ip_error_rps: float) -> tuple:
        """
        Decide whether an IP is anomalous.

        Steps:
          1. Fetch current baseline stats.
          2. If error surge detected, tighten thresholds.
          3. Compute z-score: (rate − mean) / stddev
          4. Compare rate against rate_multiplier × mean.
          5. Return (True, condition_string) if either fires.

        Returns:
          (is_anomalous: bool, condition: str)
        """
        mean, stddev, err_mean, _ = self.baseline.get_stats()

        # --- Error-surge threshold tightening ---
        zscore_thr = self.zscore_threshold
        rate_mult = self.rate_multiplier
        error_surge = False

        if err_mean > 0 and ip_error_rps >= self.error_rate_multiplier * err_mean:
            # Tighten: halve both thresholds, but keep sensible floors
            zscore_thr = max(1.5, self.zscore_threshold / 2)
            rate_mult = max(2.5, self.rate_multiplier / 2)
            error_surge = True
            logger.debug(
                f"Error surge on {ip}: err_rps={ip_error_rps:.2f} "
                f"err_mean={err_mean:.2f} → tightened thresholds"
            )

        suffix = " [error-surge thresholds]" if error_surge else ""

        # --- Z-score check ---
        if stddev > 0:
            zscore = (ip_rps - mean) / stddev
            if zscore > zscore_thr:
                cond = (
                    f"z-score={zscore:.2f} > {zscore_thr} "
                    f"(rate={ip_rps:.2f}rps mean={mean:.2f} σ={stddev:.2f})"
                    f"{suffix}"
                )
                return True, cond

        # --- Rate-multiplier check ---
        if ip_rps > rate_mult * mean:
            cond = (
                f"rate={ip_rps:.2f}rps > {rate_mult}× mean={mean:.2f}"
                f"{suffix}"
            )
            return True, cond

        return False, ""

    #  Global traffic check                                                

    def check_global(self, global_rps: float) -> tuple:
        """
        Decide whether the global request rate is anomalous.
        Same triggers as per-IP but subject to cooldown; no iptables action.

        Returns:
          (is_anomalous: bool, condition: str)
        """
        mean, stddev, _, _ = self.baseline.get_stats()

        anomalous = False
        condition = ""

        if stddev > 0:
            zscore = (global_rps - mean) / stddev
            if zscore > self.zscore_threshold:
                condition = (
                    f"GLOBAL z-score={zscore:.2f} > {self.zscore_threshold} "
                    f"(rate={global_rps:.2f}rps mean={mean:.2f} σ={stddev:.2f})"
                )
                anomalous = True

        if not anomalous and global_rps > self.rate_multiplier * mean:
            condition = (
                f"GLOBAL rate={global_rps:.2f}rps > "
                f"{self.rate_multiplier}× mean={mean:.2f}"
            )
            anomalous = True

        if anomalous:
            with self._lock:
                now = time.time()
                if now - self._last_global_alert < self.global_alert_cooldown:
                    # In cooldown — suppress alert
                    return False, ""
                self._last_global_alert = now

        return anomalous, condition
