import pandas as pd
from datetime import datetime

malicious_ips = [
    "185.220.101.1",
    "45.142.212.100",
    "194.165.16.75"
]

api_logs = [
    {"timestamp": "2024-01-15 08:00:00", "user": "alice", "src_ip": "192.168.1.1", "dst_ip": "185.220.101.1"},
    {"timestamp": "2024-01-15 08:01:00", "user": "alice", "src_ip": "192.168.1.1", "dst_ip": "8.8.8.8"},
    {"timestamp": "2024-01-15 08:02:00", "user": "bob", "src_ip": "192.168.1.2", "dst_ip": "45.142.212.100"},
    {"timestamp": "2024-01-15 08:03:00", "user": "bob", "src_ip": "192.168.1.2", "dst_ip": "45.142.212.100"},
    {"timestamp": "2024-01-15 08:04:00", "user": "charlie", "src_ip": "192.168.1.3", "dst_ip": "1.1.1.1"},
    {"timestamp": "2024-01-15 08:05:00", "user": "charlie", "src_ip": "192.168.1.3", "dst_ip": "194.165.16.75"},
    {"timestamp": "2024-01-15 08:06:00", "user": "alice", "src_ip": "192.168.1.1", "dst_ip": "194.165.16.75"},
]

df = pd.DataFrame(api_logs)
malicious_hits = df[df["dst_ip"].isin(malicious_ips)]
malicious_counts = malicious_hits.groupby("user").size()
for user, count in malicious_counts.items():
    user_malicious_ips = malicious_hits[malicious_hits["user"] == user]["dst_ip"].unique().tolist()
    print(f"ALERT: {user} hit {count} malicious connections to {user_malicious_ips}")
