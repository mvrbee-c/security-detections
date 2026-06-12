# Detects C2 beaconing by identifying repeated, evenly-spaced DNS requests from a
# single source IP to the same domain — a hallmark of malware checking in with a
# command-and-control server.

from datetime import datetime
from collections import defaultdict

# Sample DNS log entries: each records a source IP contacting a domain at a given time.
# In production this would be loaded from a SIEM, DNS server log, or network capture.
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

# Known-good domains that should never trigger a beaconing alert.
ALLOWLIST = {"updates.legit.com", "google.com"}

# Group all log entries by (src_ip, domain) so we can analyse each host-domain
# pair independently and look for repeated contact patterns.
user_events = defaultdict(list)

for entry in logs:
    # Parse the timestamp string into a datetime object for arithmetic later.
    entry["parsed_time"] = datetime.strptime(entry["timestamp"], "%Y-%m-%d %H:%M:%S")
    key = (entry["src_ip"], entry["domain"])
    user_events[key].append(entry["parsed_time"])

# Evaluate each (src_ip, domain) pair for beaconing behaviour.
for (src_ip, domain), timestamps in user_events.items():
    # Fewer than 3 contacts can't establish a repeating interval pattern.
    if len(timestamps) < 3:
        continue

    # Skip domains that are known benign — e.g. software update servers, CDNs.
    if domain in ALLOWLIST:
        continue

    timestamps.sort()

    # Calculate the gap in seconds between each consecutive contact.
    intervals = []
    for i in range(1, len(timestamps)):
        delta = (timestamps[i] - timestamps[i-1]).total_seconds()
        intervals.append(delta)

    # Low variance means the contacts are highly regular — machines beacon on a
    # fixed timer; humans browse irregularly. A 60-second tolerance accommodates
    # minor jitter while still flagging automated polling.
    interval_variance = max(intervals) - min(intervals)

    if interval_variance <= 60:
        avg_interval = sum(intervals) / len(intervals)
        print(f"BEACONING DETECTED: {src_ip} querying {domain} "
              f"{len(timestamps)} times at ~{round(avg_interval/60, 1)} min intervals "
              f"(variance: {round(interval_variance)}s)")

