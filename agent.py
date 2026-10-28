#!/usr/bin/env python3
"""SecureWatch log agent: tails a real log file and sends new lines to your SIEM.

Examples (Linux server / VM / WSL):
  python3 agent.py --url https://YOUR-APP.vercel.app --key YOUR_INGEST_KEY
  python3 agent.py --url ... --key ... --file /var/log/ufw.log --source FIREWALL
  python3 agent.py --url ... --key ... --file /var/log/nginx/access.log --source WEB

Reading /var/log/auth.log usually needs sudo. Only the Python standard library is used.
"""
import argparse, json, os, time, urllib.request

p = argparse.ArgumentParser()
p.add_argument("--url", required=True, help="your Vercel app URL")
p.add_argument("--key", required=True, help="the INGEST_KEY you set in Vercel")
p.add_argument("--file", default="/var/log/auth.log")
p.add_argument("--source", default="AUTH", help="AUTH, FIREWALL, WEB or ENDPOINT")
a = p.parse_args()

def send(events):
    req = urllib.request.Request(
        a.url.rstrip("/") + "/api/ingest", json.dumps(events).encode(),
        {"Content-Type": "application/json", "x-api-key": a.key})
    try:
        urllib.request.urlopen(req, timeout=15)
        print("sent", len(events), "events")
    except Exception as e:
        print("send failed:", e)

with open(a.file, errors="replace") as f:
    f.seek(0, os.SEEK_END)  # only new lines
    print("Watching", a.file, "-> press Ctrl+C to stop")
    batch, last = [], time.time()
    while True:
        line = f.readline()
        if line.strip():
            risky = any(w in line.lower() for w in ("failed", "invalid", "denied", "drop", "error"))
            batch.append({"source": a.source, "level": "warn" if risky else "info", "message": line.strip()})
        else:
            time.sleep(0.5)
        if batch and (len(batch) >= 20 or time.time() - last > 3):
            send(batch)
            batch, last = [], time.time()
