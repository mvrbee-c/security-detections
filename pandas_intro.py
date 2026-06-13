import pandas as pd 
from datetime import datetime

logs = [ 
    {"src_ip": "10.0.0.1", "status_code": 401, "domain": "login.corp.com"},
    {"src_ip": "10.0.0.2", "status_code": 200, "domain": "home.corp.com"},
    {"src_ip": "10.0.0.3", "status_code": 403, "domain": "admin.corp.come"},
    {"src_ip": "10.0.0.4", "status_code": 503, "domain": "api.corp.come"},
    {"src_ip": "10.0.0.1", "status_code": 401, "domain": "login.corp.com"},

]

auth_logs = [
    {"timestamp": "2024-01-15 08:00:00", "user": "alice", "src_ip": "192.168.1.1", "country": "US", "status": "success"},
    {"timestamp": "2024-01-15 08:05:00", "user": "alice", "src_ip": "85.214.132.117", "country": "DE", "status": "success"},
    {"timestamp": "2024-01-15 08:10:00", "user": "bob", "src_ip": "10.0.0.1", "country": "US", "status": "failed"},
    {"timestamp": "2024-01-15 08:11:00", "user": "bob", "src_ip": "10.0.0.1", "country": "US", "status": "failed"},
    {"timestamp": "2024-01-15 08:12:00", "user": "bob", "src_ip": "10.0.0.1", "country": "US", "status": "failed"},
    {"timestamp": "2024-01-15 08:13:00", "user": "bob", "src_ip": "10.0.0.1", "country": "US", "status": "failed"},
    {"timestamp": "2024-01-15 08:14:00", "user": "bob", "src_ip": "10.0.0.1", "country": "US", "status": "failed"},
    {"timestamp": "2024-01-15 08:00:00", "user": "charlie", "src_ip": "201.55.32.10", "country": "BR", "status": "success"},
    {"timestamp": "2024-01-15 09:00:00", "user": "charlie", "src_ip": "201.55.32.10", "country": "BR", "status": "success"},
    {"timestamp": "2024-01-15 08:30:00", "user": "alice", "src_ip": "201.55.32.10", "country": "BR", "status": "success"},
]

df = pd.DataFrame(auth_logs)

# Detection 1
failed_counts = df[df["status"] == "failed"].groupby("user").size()
failed_flag = failed_counts[failed_counts > 3]
for user, count in failed_flag.items():
    print(f"ALERT: {user} has failed login {count} times")

# Detection 2 
uniq_country_count = df.groupby("user")["country"].nunique()
country_flag = uniq_country_count[uniq_country_count > 1]
for user, count in country_flag.items():
    print(f"ALERT: {user} logged in from {count} different countries")

# Detection 3
counts = df.value_counts("src_ip")
top_ip = counts.idxmax()
top_count = counts.max()
print(f"ALERT: {top_ip} has logged in the most at {top_count} times")

