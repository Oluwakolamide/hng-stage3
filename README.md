# HNG Stage 3 — Anomaly Detection Engine

**Live Metrics Dashboard:** `http://15.222.216.23:8080` 
**Server IP:** `15.222.216.23`
**GitHub Repo:** `https://github.com/yourusername/hng-stage3`
**Blog Post:** `https://medium.com/@yourusername/how-i-built-a-ddos-detection-engine`

---

## What This Does

A production-grade anomaly detection daemon that runs alongside a Nextcloud instance and watches every incoming HTTP request in real time. It learns what normal traffic looks like, detects deviations — whether a single aggressive IP or a global traffic spike — and responds automatically.

Key behaviours:
- Tails and parses the Nginx JSON access log line by line
- Maintains two deque-based sliding windows (per-IP and global) over the last 60 seconds
- Computes a rolling 30-minute baseline (mean + stddev) recalculated every 60 seconds
- Flags anomalies via z-score > 3.0 **or** rate > 5× baseline mean — whichever fires first
- Tightens thresholds automatically when an IP is generating error surges (4xx/5xx)
- Blocks attacking IPs via `iptables DROP` within 10 seconds
- Auto-unbans on a backoff schedule: 10 min → 30 min → 2 hr → permanent
- Sends Slack alerts on every ban, unban, and global anomaly event
- Serves a live metrics dashboard refreshed every 3 seconds

---

## Language Choice — Python

Python was chosen for:
- **Clarity**: The statistical detection logic (`mean`, `stddev`, z-score) reads naturally in Python and is easy to audit against the spec.
- **Standard library deques**: `collections.deque` gives O(1) `append` and `popleft` — exactly what a sliding window needs.
- **Ecosystem**: `psutil` for system metrics, `flask` for the dashboard, `requests` for Slack webhooks — no exotic dependencies.
- **Threads**: `threading.Thread` + `threading.Lock` is sufficient for this I/O-bound workload. The monitor is mostly waiting on `readline()`; the baseline math runs briefly every 60 seconds.

---

## How the Sliding Window Works

```
             60-second window
 ─────────────────────────────────────────────────────▶ time
 │ old entries │           valid entries               │
 └─────────────────────────────────────────────────────┘
  popleft() evicts        append() adds new
  (left = oldest)         (right = newest)
```

Two deques are maintained per request:

```python
from collections import deque

ip_windows:     dict[str, deque]  # IP → deque of float timestamps
global_window:  deque             # all requests, last 60 seconds
ip_error_windows: dict[str, deque]  # IP → 4xx/5xx timestamps
```

**On every log line parsed:**

1. Call `_evict(window, now)` — pop from the LEFT while `now - window[0] > 60`.
   Because timestamps are appended in order, the leftmost is always the oldest. Each
   `popleft()` is O(1).
2. `window.append(now)` — O(1) append to the right.
3. Current rate = `len(window) / 60.0` — no state needed beyond the deque itself.

No rate-limiting library. No per-minute counters. Just timestamps and arithmetic.

---

## How the Baseline Works

### Data structure

```python
second_counts: deque of (unix_second: int, count: int)
hour_slots:    dict[int, list[int]]   # hour (0–23) → [per-second counts]
```

Every second boundary crossed by an incoming request triggers a flush:
the previous second's count is appended to `second_counts` and the appropriate
`hour_slots[hour]` list. Entries older than 1800 seconds (30 minutes) are
evicted from the left.

### Recalculation (every 60 seconds)

```
current_hour = localtime(now).tm_hour

if len(hour_slots[current_hour]) >= 120:   # at least 2 min of hourly data
    counts = hour_slots[current_hour]      # prefer time-of-day pattern
    source = "hour"
else:
    counts = [c for _, c in second_counts] # fall back to rolling window
    source = "rolling"

mean   = max(sum(counts) / len(counts),  floor_rps)   # floor: 1.0 req/s
stddev = sqrt(sum((x - mean)^2) / (n-1))              # sample stddev
```

**Floor value**: `effective_mean` never drops below `floor_rps: 1.0`. This prevents
division-by-zero z-scores and avoids false positives during dead-quiet periods.

**Why per-hour slots?** Traffic at 3 AM looks very different from traffic at noon.
Once an hourly slot accumulates enough data, it overrides the 30-minute rolling window,
giving a time-aware baseline that doesn't confuse night-time silence with an anomaly.

---

## Detection Logic

```python
# Fetch current baseline stats
mean, stddev, err_mean, _ = baseline.get_stats()

# --- Error-surge tightening ---
if ip_error_rps >= 3.0 * err_mean:
    zscore_threshold /= 2   # floor: 1.5
    rate_multiplier  /= 2   # floor: 2.5
    error_surge = True

# --- Trigger 1: Z-score ---
zscore = (ip_rps - mean) / stddev
if zscore > zscore_threshold:  # default 3.0
    → BAN

# --- Trigger 2: Rate multiplier ---
if ip_rps > rate_multiplier * mean:  # default 5×
    → BAN
```

Whichever trigger fires first wins. The z-score catches IPs that are statistically
unusual relative to the current traffic pattern. The rate multiplier is an absolute
safety net that catches extreme bursts even when variance is naturally high.

For global traffic, the same logic applies but the response is a Slack alert only
(no iptables block — we can't block "everyone").

---

## Repository Structure

```
hng-stage3/
├── detector/
│   ├── main.py          # Entry point, wires all modules
│   ├── monitor.py       # Log tail + sliding window maintenance
│   ├── baseline.py      # Rolling baseline tracker (30-min window, per-hour slots)
│   ├── detector.py      # Z-score + rate-multiplier anomaly logic
│   ├── blocker.py       # iptables ban/unban + audit log
│   ├── unbanner.py      # Backoff auto-unban scheduler
│   ├── notifier.py      # Slack webhook alerts
│   ├── dashboard.py     # Flask live metrics UI
│   ├── config.yaml      # All thresholds in one place
│   ├── requirements.txt
│   └── Dockerfile
├── nginx/
│   └── nginx.conf       # JSON access log + XFF forwarding
├── docs/
│   └── architecture.png
├── screenshots/
│   ├── Tool-running.png
│   ├── Ban-slack.png
│   ├── Unban-slack.png
│   ├── Global-alert-slack.png
│   ├── Iptables-banned.png
│   ├── Audit-log.png
│   └── Baseline-graph.png
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## Setup — Fresh VPS to Fully Running Stack

### 1. Provision a VPS

Minimum: **2 vCPU, 2 GB RAM** (Ubuntu 22.04 LTS recommended).

### 2. Install dependencies

```bash
# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

# Install Docker Compose v2
sudo apt-get install -y docker-compose-plugin

# Verify
docker --version
docker compose version
```

### 3. Clone and configure

```bash
git clone https://github.com/yourusername/hng-stage3.git
cd hng-stage3

# Create env file
cp .env.example .env
nano .env   # Set SERVER_IP, passwords, etc.
```

Edit `detector/config.yaml`:
```yaml
slack:
  webhook_url: "https://hooks.slack.com/services/YOUR/REAL/WEBHOOK"
```

### 4. Set up the dashboard subdomain

Point a DNS A record `monitor.yourdomain.com` → your server IP.

Install Nginx on the host for the subdomain proxy:

```bash
sudo apt-get install -y nginx certbot python3-certbot-nginx

# Create vhost
sudo tee /etc/nginx/sites-available/monitor << 'EOF'
server {
    listen 80;
    server_name monitor.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
EOF

sudo ln -s /etc/nginx/sites-available/monitor /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# Optional: TLS
sudo certbot --nginx -d monitor.yourdomain.com
```

### 5. Launch the stack

```bash
docker compose up -d --build

# Verify all containers are running
docker compose ps

# Follow detector logs live
docker compose logs -f detector
```

### 6. Verify

```bash
# Nginx writing JSON logs?
docker compose exec nginx tail -f /var/log/nginx/hng-access.log

# Audit log appearing?
tail -f /var/log/detector/audit.log

# Dashboard up?
curl http://localhost:8080/healthz

# iptables accessible from detector container?
docker compose exec detector iptables -L INPUT -n
```

### 7. Test detection manually

```bash
# Generate a traffic burst from another machine (or localhost):
# Replace x.x.x.x with your server IP
for i in $(seq 1 200); do curl -s http://x.x.x.x/ > /dev/null & done
wait

# Watch the detector react:
docker compose logs -f detector

# Check for banned IP:
sudo iptables -L INPUT -n | grep DROP
```

---

## Thresholds Reference (config.yaml)

| Parameter | Default | Meaning |
|---|---|---|
| `window_seconds` | 60 | Sliding window duration |
| `baseline_window_minutes` | 30 | Rolling baseline window |
| `baseline_recalc_interval` | 60 | Recalculate every N seconds |
| `zscore_threshold` | 3.0 | Z-score trip point |
| `rate_multiplier` | 5.0 | Rate must exceed mean × N |
| `error_rate_multiplier` | 3.0 | Error surge trip point |
| `floor_rps` | 1.0 | Minimum baseline mean |
| `unban_schedule` | [600, 1800, 7200] | Backoff in seconds |

---

## Troubleshooting

**iptables permission denied inside container**
```bash
# Add to docker-compose.yml under detector:
privileged: true
```

**Log file not appearing**
```bash
docker compose logs nginx   # Check Nginx started cleanly
docker volume inspect hng-stage3_HNG-nginx-logs
```

**Slack not receiving alerts**
```bash
# Test webhook directly
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"test"}' YOUR_WEBHOOK_URL
```
