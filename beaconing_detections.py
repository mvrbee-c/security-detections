from datetime import datetime
from collections import defaultdict

logs = [
  {"timestamp": "2024-01-15 08:00:00", "src_ip": "10.0.0.5", "domain": "updates.legit.com"},
  {"timestamp": "2024-01-15 08:05:00", "src_ip": "10.0.0.5", "domain": "c2server.evil.com"},
  {"timestamp": "2024-01-15 08:10:00", "src_ip": "10.0.0.5", "domain": "c2server.evil.com"},
  {"timestamp": "2024-01-15 08:15:00", "src_ip": "10.0.0.5", "domain": "c2server.evil.com"},
  {"timestamp": "2024-01-15 08:20:00", "src_ip": "10.0.0.5", "domain": "c2server.evil.com"},
  {"timestamp": "2024-01-15 08:00:00", "src_ip": "10.0.0.9", "domain": "google.com"},
  {"timestamp": "2024-01-15 08:07:00", "src_ip": "10.0.0.9", "domain": "google.com"},
  {"timestamp": "2024-01-15 08:19:00", "src_ip": "10.0.0.9", "domain": "google.com"}
]

ALLOWLIST = {"updates.legit.com", "google.com"}

user_events = defaultdict(list)

for entry in logs:
    entry["parsed_time"] = datetime.strptime(entry["timestamp"], "%Y-%m-%d %H:%M:%S")
    key = (entry["src_ip"], entry["domain"])
    user_events[key].append(entry["parsed_time"])

for (src_ip, domain), timestamps in user_events.items():
    if len(timestamps) < 3:
        continue

    if domain in ALLOWLIST:
        continue

    timestamps.sort()

    intervals = []
    for i in range(1, len(timestamps)):
        delta = (timestamps[i] - timestamps[i-1]).total_seconds()
        intervals.append(delta)

    interval_variance = max(intervals) - min(intervals)

    if interval_variance <= 60:
        avg_interval = sum(intervals) / len(intervals)
        print(f"BEACONING DETECTED: {src_ip} querying {domain} "
              f"{len(timestamps)} times at ~{round(avg_interval/60, 1)} min intervals "
              f"(variance: {round(interval_variance)}s)")

