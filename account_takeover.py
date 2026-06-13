import pandas as pd
from datetime import datetime

api_logs = [
    {"timestamp": "2024-01-15 08:00:00", "user": "alice", "src_ip": "185.220.101.1", "status": "failed"},
    {"timestamp": "2024-01-15 08:01:00", "user": "alice", "src_ip": "185.220.101.1", "status": "failed"},
    {"timestamp": "2024-01-15 08:02:00", "user": "alice", "src_ip": "185.220.101.1", "status": "failed"},
    {"timestamp": "2024-01-15 08:03:00", "user": "alice", "src_ip": "185.220.101.1", "status": "failed"},
    {"timestamp": "2024-01-15 08:04:00", "user": "alice", "src_ip": "192.168.1.105", "status": "success"},
    {"timestamp": "2024-01-15 08:00:00", "user": "bob", "src_ip": "10.0.0.1", "status": "failed"},
    {"timestamp": "2024-01-15 08:01:00", "user": "bob", "src_ip": "10.0.0.1", "status": "failed"},
    {"timestamp": "2024-01-15 08:02:00", "user": "bob", "src_ip": "10.0.0.1", "status": "success"},
    {"timestamp": "2024-01-15 08:00:00", "user": "charlie", "src_ip": "10.0.0.5", "status": "failed"},
    {"timestamp": "2024-01-15 08:01:00", "user": "charlie", "src_ip": "10.0.0.5", "status": "failed"},
    {"timestamp": "2024-01-15 08:02:00", "user": "charlie", "src_ip": "10.0.0.5", "status": "failed"},
    {"timestamp": "2024-01-15 08:03:00", "user": "charlie", "src_ip": "10.0.0.5", "status": "failed"},
    {"timestamp": "2024-01-15 08:04:00", "user": "charlie", "src_ip": "10.0.0.5", "status": "success"},
]

df = pd.DataFrame(api_logs)

failed_logins = df[df["status"] == "failed"].groupby("user").size()
failed_flag = failed_logins[failed_logins > 3]

for user, count in failed_flag.items():
    failure_ips = df[(df["user"] == user) & (df["status"] == "failed")]["src_ip"].unique().tolist()
    success_ips = df[(df["user"] == user) & (df["status"] == "success")]["src_ip"].unique().tolist()
    
    for success_ip in success_ips:
        if success_ip not in failure_ips:
            print(f"ALERT: Possible account takeover - {user} had {count} failed logins then succeeded from new IP {success_ip}")