"""
main.py — HNG Anomaly Detection Engine entry point.

Wires all modules together and launches the following threads:
  1. baseline.recalculate_loop()  — background baseline recalculation (every 60s)
  2. unbanner.run()               — background auto-unban scheduler (polls every 5s)
  3. dashboard.run()              — Flask web metrics UI (port 8080)
  4. monitor.run()                — foreground log tail (runs in main thread)

All inter-module communication goes through shared objects rather than
queues; each module protects its own state with threading.Lock().

Usage:
  python main.py [--config /path/to/config.yaml]
"""

import sys
import os
import argparse
import logging
import threading
import time
import yaml

from baseline import BaselineTracker
from detector import AnomalyDetector
from blocker import IPBlocker
from unbanner import AutoUnbanner
from notifier import SlackNotifier
from monitor import LogMonitor
from dashboard import Dashboard


def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        handlers=[
            logging.StreamHandler(sys.stdout),
        ],
    )


def main() -> None:
    setup_logging()
    logger = logging.getLogger("main")

    parser = argparse.ArgumentParser(description="HNG Anomaly Detection Engine")
    parser.add_argument(
        "--config",
        default=os.path.join(os.path.dirname(__file__), "config.yaml"),
        help="Path to config.yaml",
    )
    args = parser.parse_args()

    logger.info(f"Loading config from: {args.config}")
    with open(args.config) as f:
        config = yaml.safe_load(f)

    # Ensure audit log directory exists
    audit_dir = os.path.dirname(config["audit_log"])
    if audit_dir:
        os.makedirs(audit_dir, exist_ok=True)

    logger.info("Initialising modules…")

    # Instantiate modules
    notifier = SlackNotifier(config)
    blocker = IPBlocker(config)
    baseline = BaselineTracker(config)
    detector = AnomalyDetector(config, baseline)
    unbanner = AutoUnbanner(config, blocker, notifier)
    monitor = LogMonitor(config, baseline, detector, blocker, notifier, unbanner)
    dashboard = Dashboard(config, monitor, baseline, blocker)

    # Startup audit entry
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    try:
        with open(config["audit_log"], "a") as f:
            f.write(f"[{ts}] DAEMON_START * | HNG Anomaly Engine started | rate=0 | baseline=0 | duration=ongoing\n")
    except Exception:
        pass

    # Background threads
    threads = [
        threading.Thread(
            target=baseline.recalculate_loop,
            name="baseline-recalc",
            daemon=True,
        ),
        threading.Thread(
            target=unbanner.run,
            name="auto-unbanner",
            daemon=True,
        ),
        threading.Thread(
            target=dashboard.run,
            name="dashboard",
            daemon=True,
        ),
    ]

    for t in threads:
        t.start()
        logger.info(f"Started thread: {t.name}")

    logger.info("=" * 60)
    logger.info("HNG Anomaly Detection Engine is live")
    logger.info(f"  Log file  : {config['nginx']['log_path']}")
    logger.info(f"  Dashboard : http://0.0.0.0:{config['dashboard']['port']}")
    logger.info(f"  Audit log : {config['audit_log']}")
    logger.info("=" * 60)

    # Main thread runs the log monitor (blocks until process is killed)
    try:
        monitor.run()
    except KeyboardInterrupt:
        logger.info("Shutting down — received KeyboardInterrupt")
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        try:
            with open(config["audit_log"], "a") as f:
                f.write(f"[{ts}] DAEMON_STOP * | HNG Anomaly Engine stopped | rate=0 | baseline=0 | duration=n/a\n")
        except Exception:
            pass


if __name__ == "__main__":
    main()
