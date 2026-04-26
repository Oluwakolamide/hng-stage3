"""
dashboard.py — Live metrics web dashboard.

Served via Flask on the configured port (default 8080).
The frontend polls /api/metrics every 3 seconds via JavaScript fetch()
and updates the DOM in-place — no page reload needed.

Displays:
  - Global req/s (live)
  - Banned IPs list with level and unban time
  - Top 10 source IPs by current rate
  - CPU and memory usage (via psutil)
  - Effective mean / stddev from baseline
  - Daemon uptime
  - Baseline history chart (Chart.js)

The domain/subdomain serving this dashboard is what gets submitted
for grading. Nextcloud is accessible by IP only.
"""

import time
import logging
import threading

import psutil
from flask import Flask, jsonify, render_template_string

logger = logging.getLogger("dashboard")

# --------------------------------------------------------------------------- #
#  HTML template — served at /                                                 #
# --------------------------------------------------------------------------- #

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>HNG Anomaly Engine — Live Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #f0f6fc; --muted: #8b949e; --blue: #58a6ff;
    --green: #3fb950; --red: #f85149; --orange: #f0883e;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Courier New', monospace; background: var(--bg); color: var(--text); padding: 24px; }
  h1 { font-size: 1.4rem; color: var(--blue); border-bottom: 1px solid var(--border); padding-bottom: 12px; margin-bottom: 20px; }
  h2 { font-size: 1rem; color: var(--muted); margin: 20px 0 10px; text-transform: uppercase; letter-spacing: 1px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 20px; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
  .card .label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px; }
  .card .value { font-size: 1.8rem; font-weight: bold; }
  .val-good { color: var(--green); }
  .val-warn { color: var(--orange); }
  .val-bad  { color: var(--red); }
  .val-blue { color: var(--blue); }
  table { width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; margin-bottom: 20px; }
  th { background: #21262d; color: var(--muted); padding: 10px 14px; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }
  td { padding: 9px 14px; border-bottom: 1px solid var(--border); font-size: 13px; }
  tr:last-child td { border-bottom: none; }
  .banned-ip { color: var(--red); }
  .hot-ip { color: var(--orange); }
  .empty-row td { color: var(--muted); font-style: italic; }
  .chart-wrap { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 20px; }
  #status-bar { color: var(--muted); font-size: 11px; margin-top: 8px; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; margin-left: 6px; }
  .badge-perm { background: #3d1f1f; color: var(--red); }
  .badge-temp { background: #1f2d1f; color: var(--green); }
</style>
</head>
<body>
<h1>🛡️ HNG Anomaly Detection Engine &mdash; Live Dashboard</h1>

<div class="grid">
  <div class="card"><div class="label">Global Req/s</div><div class="value val-blue" id="g-rps">—</div></div>
  <div class="card"><div class="label">Banned IPs</div><div class="value val-bad" id="g-banned">—</div></div>
  <div class="card"><div class="label">Baseline Mean</div><div class="value val-blue" id="g-mean">—</div></div>
  <div class="card"><div class="label">Baseline σ</div><div class="value val-blue" id="g-stddev">—</div></div>
  <div class="card"><div class="label">CPU</div><div class="value val-warn" id="g-cpu">—</div></div>
  <div class="card"><div class="label">Memory</div><div class="value val-warn" id="g-mem">—</div></div>
  <div class="card"><div class="label">Uptime</div><div class="value val-good" id="g-uptime">—</div></div>
</div>

<h2>Banned IPs</h2>
<table>
  <thead><tr><th>IP Address</th><th>Level</th><th>Banned At</th><th>Unban At</th></tr></thead>
  <tbody id="banned-body"><tr class="empty-row"><td colspan="4">No banned IPs</td></tr></tbody>
</table>

<h2>Top 10 Source IPs (last 60s)</h2>
<table>
  <thead><tr><th>IP Address</th><th>Req/s</th><th>vs Baseline</th></tr></thead>
  <tbody id="top-body"><tr class="empty-row"><td colspan="3">No traffic yet</td></tr></tbody>
</table>

<h2>Baseline History</h2>
<div class="chart-wrap">
  <canvas id="baseline-chart" height="90"></canvas>
</div>

<div id="status-bar">Connecting…</div>

<script>
const chart = new Chart(document.getElementById('baseline-chart'), {
  type: 'line',
  data: {
    labels: [],
    datasets: [
      { label: 'Mean req/s', data: [], borderColor: '#58a6ff', backgroundColor: 'rgba(88,166,255,0.08)', tension: 0.3, fill: true },
      { label: 'Mean + 3σ', data: [], borderColor: '#f85149', borderDash: [4,3], backgroundColor: 'transparent', tension: 0.3 }
    ]
  },
  options: {
    animation: false,
    plugins: { legend: { labels: { color: '#8b949e', font: { family: 'Courier New' } } } },
    scales: {
      x: { ticks: { color: '#8b949e', font: { size: 10 } }, grid: { color: '#21262d' } },
      y: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' }, beginAtZero: true }
    }
  }
});

function fmtTime(ts) {
  return new Date(ts * 1000).toISOString().substr(11, 8);
}
function fmtUptime(s) {
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = Math.floor(s % 60);
  return h + 'h ' + m + 'm ' + sec + 's';
}
function colorForRate(rps, mean) {
  if (rps > mean * 3) return 'hot-ip';
  return '';
}

async function refresh() {
  try {
    const r = await fetch('/api/metrics');
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();

    document.getElementById('g-rps').textContent = d.global_rps.toFixed(2);
    document.getElementById('g-banned').textContent = d.banned_count;
    document.getElementById('g-mean').textContent = d.mean.toFixed(3);
    document.getElementById('g-stddev').textContent = d.stddev.toFixed(3);
    document.getElementById('g-cpu').textContent = d.cpu_percent.toFixed(1) + '%';
    document.getElementById('g-mem').textContent = d.memory_percent.toFixed(1) + '%';
    document.getElementById('g-uptime').textContent = fmtUptime(d.uptime);

    // Banned IPs table
    const bannedEntries = Object.entries(d.banned_ips);
    if (bannedEntries.length === 0) {
      document.getElementById('banned-body').innerHTML =
        '<tr class="empty-row"><td colspan="4">No banned IPs</td></tr>';
    } else {
      document.getElementById('banned-body').innerHTML = bannedEntries.map(([ip, info]) => {
        const perm = !info.unban_time;
        const badge = perm ? '<span class="badge badge-perm">PERMANENT</span>' : '<span class="badge badge-temp">temp</span>';
        const unbanAt = info.unban_time ? fmtTime(info.unban_time) : '—';
        return `<tr><td class="banned-ip">${ip}${badge}</td><td>${info.level}</td><td>${fmtTime(info.ban_time)}</td><td>${unbanAt}</td></tr>`;
      }).join('');
    }

    // Top IPs table
    if (!d.top_ips || d.top_ips.length === 0) {
      document.getElementById('top-body').innerHTML =
        '<tr class="empty-row"><td colspan="3">No traffic yet</td></tr>';
    } else {
      document.getElementById('top-body').innerHTML = d.top_ips.map(([ip, rps]) => {
        const mult = d.mean > 0 ? (rps / d.mean).toFixed(1) + '×' : '—';
        const cls = colorForRate(rps, d.mean);
        return `<tr><td class="${cls}">${ip}</td><td>${rps.toFixed(3)}</td><td>${mult}</td></tr>`;
      }).join('');
    }

    // Baseline chart update
    if (d.baseline_history && d.baseline_history.length > 0) {
      const labels = d.baseline_history.map(p => fmtTime(p.timestamp));
      const means  = d.baseline_history.map(p => p.mean);
      const upper  = d.baseline_history.map(p => p.mean + 3 * p.stddev);
      chart.data.labels = labels;
      chart.data.datasets[0].data = means;
      chart.data.datasets[1].data = upper;
      chart.update();
    }

    document.getElementById('status-bar').textContent =
      'Last updated: ' + new Date().toISOString() + ' | Total req seen: ' + d.total_requests;
  } catch (e) {
    document.getElementById('status-bar').textContent = 'Fetch error: ' + e;
  }
}

refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
"""


class Dashboard:
    def __init__(self, config, monitor, baseline, blocker):
        self.config = config
        self.monitor = monitor
        self.baseline = baseline
        self.blocker = blocker
        self.port: int = config["dashboard"]["port"]
        self._start_time: float = time.time()

        self.app = Flask(__name__)
        self._register_routes()

    def _register_routes(self) -> None:
        monitor = self.monitor
        baseline = self.baseline
        blocker = self.blocker
        start_time = self._start_time

        @self.app.route("/")
        def index():
            return render_template_string(DASHBOARD_HTML)

        @self.app.route("/api/metrics")
        def metrics():
            mean, stddev, err_mean, _ = baseline.get_stats()
            banned = blocker.get_banned_ips()
            top_ips = monitor.get_top_ips(10)
            history = baseline.get_history()

            return jsonify(
                {
                    "global_rps": monitor.get_global_rps(),
                    "banned_count": len(banned),
                    "banned_ips": {
                        ip: {
                            "ban_time": info["ban_time"],
                            "level": info["level"],
                            "unban_time": info.get("unban_time"),
                        }
                        for ip, info in banned.items()
                    },
                    "top_ips": top_ips,
                    "mean": mean,
                    "stddev": stddev,
                    "err_mean": err_mean,
                    "cpu_percent": psutil.cpu_percent(interval=None),
                    "memory_percent": psutil.virtual_memory().percent,
                    "uptime": time.time() - start_time,
                    "total_requests": monitor.total_requests,
                    "baseline_history": history,
                }
            )

        @self.app.route("/healthz")
        def health():
            return jsonify({"status": "ok", "uptime": time.time() - start_time})

    def run(self) -> None:
        logger.info(f"Dashboard starting on port {self.port}")
        # Disable Flask request logging to keep stdout clean
        log = logging.getLogger("werkzeug")
        log.setLevel(logging.ERROR)
        self.app.run(
            host="0.0.0.0",
            port=self.port,
            debug=False,
            use_reloader=False,
            threaded=True,
        )
