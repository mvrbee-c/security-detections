import pandas as pd
from datetime import datetime


events = [
    {"timestamp": "2024-01-15 08:00:00", "user": "alice", "status": "failed"},
    {"timestamp": "2024-01-15 08:02:00", "user": "alice", "status": "failed"},
    {"timestamp": "2024-01-15 08:04:00", "user": "alice", "status": "failed"},
    {"timestamp": "2024-01-15 08:06:00", "user": "alice", "status": "failed"},
    {"timestamp": "2024-01-15 08:08:00", "user": "alice", "status": "failed"},
    {"timestamp": "2024-01-15 08:09:00", "user": "alice", "status": "failed"},
    {"timestamp": "2024-01-15 08:30:00", "user": "alice", "status": "failed"},
    {"timestamp": "2024-01-15 08:01:00", "user": "bob", "status": "failed"},
    {"timestamp": "2024-01-15 08:02:00", "user": "bob", "status": "failed"},
    {"timestamp": "2024-01-15 08:03:00", "user": "bob", "status": "failed"},
    {"timestamp": "2024-01-15 08:20:00", "user": "charlie", "status": "failed"},
    {"timestamp": "2024-01-15 08:21:00", "user": "charlie", "status": "failed"},
]

df = pd.DataFrame(events)
df["parsed_time"] = pd.to_datetime(df["timestamp"])
failed = df[df["status"] == "failed"].groupby("user")


for user, group in failed:
    timestamps = group["parsed_time"].sort_values().tolist()
    for counter, current_time in enumerate(timestamps):
        window = [each_event for each_event in timestamps if 0 <= (each_event - current_time).total_seconds() <= 600]
        if len(window) > 5:
            print(f"ALERT: {user} had {len(window)} failed logins within a 10 minute window")
            break
