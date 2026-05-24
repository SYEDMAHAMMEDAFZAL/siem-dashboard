from flask import Flask, render_template_string
from log_generator import generate_logs
from detector import load_logs, analyse_logs, get_stats

app = Flask(__name__)

HTML = '''
<!DOCTYPE html>
<html>
<head>
<title>SIEM Dashboard — Afzal</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { background:#0a0e1a; color:white; font-family:monospace; padding:20px; }
h1 { color:#00ff88; text-align:center; padding:20px; font-size:28px; }
h2 { color:#00bfff; margin:20px 0 10px; }
.stats { display:flex; gap:15px; flex-wrap:wrap; margin:20px 0; }
.card { background:#0f1a2e; border-radius:10px; padding:20px; flex:1; min-width:150px; text-align:center; }
.card h3 { font-size:36px; font-weight:bold; }
.critical { border:2px solid #ff4444; } .critical h3 { color:#ff4444; }
.high { border:2px solid #ff8800; } .high h3 { color:#ff8800; }
.medium { border:2px solid #ffd700; } .medium h3 { color:#ffd700; }
.low { border:2px solid #00bfff; } .low h3 { color:#00bfff; }
.total { border:2px solid #00ff88; } .total h3 { color:#00ff88; }
table { width:100%; border-collapse:collapse; background:#0f1a2e; border-radius:10px; overflow:hidden; }
th { background:#00ff88; color:#0a0e1a; padding:12px; text-align:left; }
td { padding:10px 12px; border-bottom:1px solid #1a2a3a; font-size:13px; }
tr:hover { background:#1a2a3a; }
.CRITICAL { color:#ff4444; font-weight:bold; }
.HIGH { color:#ff8800; font-weight:bold; }
.MEDIUM { color:#ffd700; font-weight:bold; }
.LOW { color:#00bfff; }
.footer { text-align:center; margin-top:30px; color:#888; }
</style>
</head>
<body>
<h1>🔐 SIEM THREAT DETECTION DASHBOARD</h1>
<p style="text-align:center;color:#888">Author: S.Md.Afzal | github.com/SYEDMAHAMMEDAFZAL</p>

<div class="stats">
  <div class="card total"><p>Total Events</p><h3>{{s.total_logs}}</h3></div>
  <div class="card total"><p>Total Alerts</p><h3>{{s.total_alerts}}</h3></div>
  <div class="card critical"><p>CRITICAL</p><h3>{{s.critical}}</h3></div>
  <div class="card high"><p>HIGH</p><h3>{{s.high}}</h3></div>
  <div class="card medium"><p>MEDIUM</p><h3>{{s.medium}}</h3></div>
  <div class="card low"><p>LOW</p><h3>{{s.low}}</h3></div>
</div>

<h2>🚨 Active Alerts</h2>
<table>
<tr><th>Time</th><th>Alert</th><th>Source IP</th><th>Severity</th><th>Recommendation</th></tr>
{% for a in alerts %}
<tr>
  <td>{{a.timestamp}}</td>
  <td>{{a.alert_type}}</td>
  <td>{{a.source_ip}}</td>
  <td class="{{a.severity}}">{{a.severity}}</td>
  <td style="font-size:11px">{{a.recommendation}}</td>
</tr>
{% endfor %}
</table>

<h2>🔥 Top Attacker IPs</h2>
<table>
<tr><th>IP Address</th><th>Event Count</th></tr>
{% for ip,count in s.top_ips %}
<tr><td>{{ip}}</td><td>{{count}}</td></tr>
{% endfor %}
</table>

<div class="footer">
  <p>S.Md.Afzal | SIEM Dashboard v1.0 | github.com/SYEDMAHAMMEDAFZAL</p>
</div>
</body>
</html>
'''

@app.route('/')
def dashboard():
    generate_logs(100)
    logs   = load_logs()
    alerts = analyse_logs(logs)
    stats  = get_stats(logs, alerts)
    return render_template_string(HTML, alerts=alerts, s=type('S', (), stats)())

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
