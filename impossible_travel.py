from datetime import datetime
from collections import defaultdict
from itertools import combinations

logs = [
  {"timestamp": "2024-01-15 08:00:00", "user_id": "user_001", "ip": "192.168.1.1", "country": "US"},
  {"timestamp": "2024-01-15 08:45:00", "user_id": "user_001", "ip": "85.214.132.117", "country": "DE"},
  {"timestamp": "2024-01-15 09:00:00", "user_id": "user_002", "ip": "10.0.0.1", "country": "US"},
  {"timestamp": "2024-01-15 09:30:00", "user_id": "user_002", "ip": "10.0.0.2", "country": "US"},
  {"timestamp": "2024-01-15 10:00:00", "user_id": "user_001", "ip": "201.55.32.10", "country": "BR"}
]

user_events = defaultdict(list)

for entry in logs:
    entry["parsed_time"] = datetime.strptime(entry["timestamp"], "%Y-%m-%d %H:%M:%S")
    user_events[entry["user_id"]].append(entry)

flagged = set()

for user_id, events in user_events.items():
    events.sort(key=lambda x: x["parsed_time"])
    for a, b in combinations(events, 2):
        time_diff = abs((b["parsed_time"] - a["parsed_time"]).total_seconds())
        if time_diff <= 7200 and a["ip"] != b["ip"] and a["country"] != b["country"]:
            flagged.add(user_id)
            print(f"ALERT: {user_id} logged in from {a['ip']} ({a['country']}) at {a['timestamp']} "
                  f"and {b['ip']} ({b['country']}) at {b['timestamp']} "
                  f"— {round(time_diff/60, 1)} minutes apart")

if not flagged:
    print("No suspicious activity detected")