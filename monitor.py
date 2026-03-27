#!/usr/bin/env python3
"""
Security Monitor — Minimal ADB Log Analyzer
Detects suspicious Android activity via logcat.

Usage:
  Live monitoring:  python monitor.py
  Batch file:       python monitor.py --file dump.txt
  With dashboard:   python monitor.py --web
  Specific device:  python monitor.py --device <serial>
"""

import subprocess
import re
import json
import time
import math
import argparse
import threading
from collections import deque, defaultdict
from datetime import datetime
from pathlib import Path

# ─── ANSI Colors ──────────────────────────────────────────────────────────────
class C:
    RED    = '\033[91m'
    YELLOW = '\033[93m'
    GREEN  = '\033[92m'
    CYAN   = '\033[96m'
    GREY   = '\033[90m'
    WHITE  = '\033[97m'
    BOLD   = '\033[1m'
    RESET  = '\033[0m'

LEVEL_COLOR = {'V': C.GREY, 'D': C.GREY, 'I': C.WHITE, 'W': C.YELLOW, 'E': C.RED, 'F': C.RED}
SEV_COLOR   = {'LOW': C.GREEN, 'MEDIUM': C.YELLOW, 'HIGH': C.RED, 'CRITICAL': C.RED}

# ─── Log Parser ───────────────────────────────────────────────────────────────
# Matches: MM-DD HH:MM:SS.mmm  PID  TID LEVEL TAG: message
LOG_RE = re.compile(
    r'^(\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2}\.\d{3})\s+(\d+)\s+(\d+)\s+([VDIWEF])\s+([\w/.@:-]+)\s*:\s+(.*)$'
)

def parse_line(raw: str) -> dict | None:
    m = LOG_RE.match(raw.strip())
    if not m:
        return None
    return {
        'date':    m.group(1),
        'time':    m.group(2),
        'pid':     int(m.group(3)),
        'tid':     int(m.group(4)),
        'level':   m.group(5),
        'tag':     m.group(6),
        'message': m.group(7),
        'raw':     raw.strip(),
        'ts':      time.time(),
    }

# ─── Rule Engine ──────────────────────────────────────────────────────────────
LEVEL_NUM = {'V': 0, 'D': 1, 'I': 2, 'W': 3, 'E': 4, 'F': 5}

def _match_condition(entry: dict, cond: dict) -> bool:
    raw_val = entry.get(cond['field'], '')
    field   = str(raw_val).lower()
    val     = cond['value'].lower()
    op      = cond['op']
    if op == 'contains':   return val in field
    if op == 'equals':     return field == val
    if op == 'startswith': return field.startswith(val)
    if op == 'regex':      return bool(re.search(val, field, re.I))
    if op == 'gte':        return LEVEL_NUM.get(entry.get('level', 'V'), 0) >= LEVEL_NUM.get(val.upper(), 0)
    return False

def check_rules(entry: dict, rules: list) -> list:
    hits = []
    for rule in rules:
        logic = rule.get('logic', 'AND')
        conds = rule['conditions']
        matched = all(_match_condition(entry, c) for c in conds) if logic == 'AND' \
             else any(_match_condition(entry, c) for c in conds)
        if matched:
            hits.append({
                'rule_id':  rule['id'],
                'name':     rule['name'],
                'severity': rule['severity'],
                'score':    rule['score'],
                'entry':    entry,
                'engine':   'RULE',
            })
    return hits

# ─── Frequency Analyzer ───────────────────────────────────────────────────────
# Per-tag rate thresholds (events per 60 seconds)
RATE_THRESHOLDS = {
    'SmsManager':       5,
    'LocationManager':  10,
    'CameraService':    3,
    'AudioFlinger':     3,
    'PackageManager':   8,
    'WifiManager':      20,
    'BluetoothAdapter': 15,
    'DownloadManager':  10,
}
DEFAULT_RATE = 120

class FrequencyAnalyzer:
    def __init__(self, window: int = 60):
        self.window = window
        self._buckets: dict[str, deque] = defaultdict(deque)

    def check(self, entry: dict) -> dict | None:
        tag = entry['tag']
        now = entry['ts']
        dq  = self._buckets[tag]
        dq.append(now)
        while dq and dq[0] < now - self.window:
            dq.popleft()
        count     = len(dq)
        threshold = RATE_THRESHOLDS.get(tag, DEFAULT_RATE)
        if count > threshold:
            ratio = count / threshold
            score = min(75, 30 + int(ratio * 15))
            sev   = 'HIGH' if ratio > 3 else 'MEDIUM'
            return {
                'rule_id':  'FREQ_ANOMALY',
                'name':     f'High rate: {tag} ({count} events/60s, limit {threshold})',
                'severity': sev,
                'score':    score,
                'entry':    entry,
                'engine':   'FREQ',
            }
        return None

# ─── Entropy Check ────────────────────────────────────────────────────────────
def _entropy(s: str) -> float:
    if len(s) < 8:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())

def check_entropy(entry: dict) -> dict | None:
    msg = entry['message']
    if len(msg) < 32:
        return None
    h = _entropy(msg)
    if h > 5.5:
        return {
            'rule_id':  'HIGH_ENTROPY',
            'name':     f'High-entropy payload (H={h:.2f}) in {entry["tag"]}',
            'severity': 'MEDIUM',
            'score':    55,
            'entry':    entry,
            'engine':   'ENTROPY',
        }
    return None

# ─── Risk Aggregator ──────────────────────────────────────────────────────────
ENGINE_WEIGHT = {'RULE': 1.0, 'FREQ': 0.7, 'ENTROPY': 0.75, 'ML': 0.85}
DECAY_LAMBDA  = 0.005   # half-life ≈ 140 seconds

class RiskAggregator:
    def __init__(self, event_window: int = 300):
        self._events: deque = deque()
        self._window = event_window

    def add(self, event: dict):
        self._events.append({'event': event, 'ts': time.time()})

    def score(self) -> float:
        now    = time.time()
        total  = 0.0
        active = deque()
        for item in self._events:
            age = now - item['ts']
            if age > self._window:
                continue
            active.append(item)
            w      = ENGINE_WEIGHT.get(item['event'].get('engine', 'RULE'), 1.0)
            decay  = math.exp(-DECAY_LAMBDA * age)
            total += item['event']['score'] * w * decay
        self._events = active
        return min(100.0, total)

    def level(self) -> tuple[str, float, str]:
        s = self.score()
        if s >= 70:
            return 'HIGH',   s, C.RED
        if s >= 30:
            return 'MEDIUM', s, C.YELLOW
        return             'LOW',   s, C.GREEN

# ─── Alert Printer ────────────────────────────────────────────────────────────
_last_alert: dict[str, float] = {}
_suppress_secs = 60

# Shared event log for the web dashboard
_event_log: deque = deque(maxlen=200)

def maybe_alert(event: dict, aggregator: RiskAggregator) -> bool:
    rule_id = event['rule_id']
    now     = time.time()
    if now - _last_alert.get(rule_id, 0) < _suppress_secs:
        return False
    _last_alert[rule_id] = now
    aggregator.add(event)

    entry  = event['entry']
    sev    = event['severity']
    color  = SEV_COLOR.get(sev, C.WHITE)
    level, score, lcolor = aggregator.level()

    line = (
        f"\n{color}{C.BOLD}[{sev}] {event['name']}{C.RESET}\n"
        f"  {C.GREY}{entry['time']}  tag={entry['tag']}  pid={entry['pid']}  "
        f"engine={event['engine']}{C.RESET}\n"
        f"  {C.GREY}{entry['message'][:140]}{C.RESET}\n"
        f"  {lcolor}Risk {score:.0f}/100  →  {level}{C.RESET}"
    )
    print(line)

    # store plain version for web dashboard
    _event_log.append({
        'ts':       datetime.fromtimestamp(now).strftime('%H:%M:%S'),
        'severity': sev,
        'rule_id':  rule_id,
        'name':     event['name'],
        'tag':      entry['tag'],
        'pid':      entry['pid'],
        'message':  entry['message'][:200],
        'score':    f"{score:.0f}",
        'level':    level,
        'engine':   event['engine'],
    })
    return True

# ─── Web Dashboard ────────────────────────────────────────────────────────────
DASHBOARD_HTML = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="5">
  <title>Security Monitor</title>
  <style>
    body { font-family: monospace; background: #0d0d0d; color: #ccc; margin: 0; padding: 20px; }
    h1   { color: #00e5ff; margin-bottom: 4px; }
    .sub { color: #555; font-size: 12px; margin-bottom: 24px; }
    .gauge { display: inline-block; padding: 12px 28px; border-radius: 6px;
             font-size: 28px; font-weight: bold; margin-bottom: 24px; }
    .LOW      { background: #1a2e1a; color: #4caf50; border: 1px solid #4caf50; }
    .MEDIUM   { background: #2e2a1a; color: #ff9800; border: 1px solid #ff9800; }
    .HIGH     { background: #2e1a1a; color: #f44336; border: 1px solid #f44336; }
    .CRITICAL { background: #2e1a1a; color: #f44336; border: 1px solid #f44336; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th    { text-align: left; color: #555; padding: 6px 10px; border-bottom: 1px solid #222; }
    td    { padding: 6px 10px; border-bottom: 1px solid #1a1a1a; }
    tr:hover td { background: #141414; }
    .sev-HIGH     { color: #f44336; font-weight: bold; }
    .sev-CRITICAL { color: #f44336; font-weight: bold; }
    .sev-MEDIUM   { color: #ff9800; }
    .sev-LOW      { color: #4caf50; }
    .engine { color: #555; font-size: 11px; }
    .msg    { color: #888; max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .empty  { color: #333; padding: 40px; text-align: center; }
  </style>
</head>
<body>
  <h1>Security Monitor</h1>
  <div class="sub">Auto-refreshes every 5 seconds &mdash; {{ count }} events</div>

  <div class="gauge {{ level }}">{{ level }}&nbsp;&nbsp;{{ score }}/100</div>

  {% if events %}
  <table>
    <tr>
      <th>Time</th><th>Severity</th><th>Rule</th><th>Tag</th>
      <th>PID</th><th>Engine</th><th>Message</th>
    </tr>
    {% for e in events %}
    <tr>
      <td>{{ e.ts }}</td>
      <td class="sev-{{ e.severity }}">{{ e.severity }}</td>
      <td>{{ e.name }}</td>
      <td>{{ e.tag }}</td>
      <td>{{ e.pid }}</td>
      <td class="engine">{{ e.engine }}</td>
      <td class="msg" title="{{ e.message }}">{{ e.message }}</td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <div class="empty">No suspicious events detected yet.</div>
  {% endif %}
</body>
</html>
"""

def start_dashboard(aggregator: RiskAggregator, port: int = 5000):
    try:
        from flask import Flask, render_template_string
    except ImportError:
        print(f"{C.YELLOW}Flask not installed — dashboard disabled. Run: pip install flask{C.RESET}")
        return

    app = Flask(__name__)

    @app.route('/')
    def index():
        level, score, _ = aggregator.level()
        events = list(reversed(list(_event_log)))
        return render_template_string(
            DASHBOARD_HTML,
            events=events,
            level=level,
            score=f"{score:.0f}",
            count=len(events),
        )

    def run():
        import logging
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)
        app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

    t = threading.Thread(target=run, daemon=True)
    t.start()
    print(f"{C.CYAN}Dashboard → http://localhost:{port}/{C.RESET}")

# ─── Core Monitor Loop ────────────────────────────────────────────────────────
def monitor(device: str | None, batch_file: str | None, rules_path: str, web: bool, port: int):
    rules_file = Path(rules_path)
    if not rules_file.exists():
        print(f"{C.RED}rules.json not found at {rules_path}{C.RESET}")
        return

    with open(rules_file) as f:
        rules = json.load(f)

    freq = FrequencyAnalyzer()
    agg  = RiskAggregator()

    if web:
        start_dashboard(agg, port)

    print(f"\n{C.CYAN}{C.BOLD}Security Monitor{C.RESET}  "
          f"{C.GREY}{len(rules)} rules loaded{C.RESET}")

    if batch_file:
        print(f"{C.GREY}Batch mode → {batch_file}{C.RESET}\n")
        source = open(batch_file)
    else:
        cmd = ['adb']
        if device:
            cmd += ['-s', device]
        cmd += ['logcat', '-v', 'threadtime']
        print(f"{C.GREY}Live mode  → {' '.join(cmd)}{C.RESET}")
        print(f"{C.GREY}Make sure: adb tcpip 5555  (run once with USB){C.RESET}\n")
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            source = proc.stdout
        except FileNotFoundError:
            print(f"{C.RED}adb not found. Install Android SDK Platform Tools and add to PATH.{C.RESET}")
            return

    lines_parsed = 0
    events_fired = 0

    try:
        for raw in source:
            entry = parse_line(raw)
            if not entry:
                continue
            lines_parsed += 1

            candidates = check_rules(entry, rules)
            freq_event = freq.check(entry)
            entr_event = check_entropy(entry)

            if freq_event:
                candidates.append(freq_event)
            if entr_event:
                candidates.append(entr_event)

            for ev in candidates:
                if maybe_alert(ev, agg):
                    events_fired += 1

    except KeyboardInterrupt:
        pass
    finally:
        if batch_file:
            source.close()
        _, score, lcolor = agg.level()
        level, *_ = agg.level()
        print(f"\n{C.GREY}─── Summary ───────────────────────────────{C.RESET}")
        print(f"  Lines parsed : {lines_parsed:,}")
        print(f"  Events fired : {events_fired}")
        print(f"  Final risk   : {lcolor}{level} ({score:.0f}/100){C.RESET}\n")

# ─── Entry Point ──────────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(description='Android Security Monitor via ADB')
    p.add_argument('--device', '-d', metavar='SERIAL',  help='ADB device serial (adb devices)')
    p.add_argument('--file',   '-f', metavar='FILE',    help='Batch logcat file to analyze')
    p.add_argument('--rules',  '-r', default='rules.json', metavar='FILE', help='Detection rules JSON')
    p.add_argument('--web',    '-w', action='store_true', help='Start web dashboard at localhost:5000')
    p.add_argument('--port',   '-p', type=int, default=5000, help='Dashboard port (default 5000)')
    args = p.parse_args()

    monitor(
        device     = args.device,
        batch_file = args.file,
        rules_path = args.rules,
        web        = args.web,
        port       = args.port,
    )

if __name__ == '__main__':
    main()
