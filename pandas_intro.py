import pandas as pd 

logs = [ 
    {"src_ip": "10.0.0.1", "status_code": 401, "domain": "login.corp.com"},
    {"src_ip": "10.0.0.2", "status_code": 200, "domain": "home.corp.com"},
    {"src_ip": "10.0.0.3", "status_code": 403, "domain": "admin.corp.come"},
    {"src_ip": "10.0.0.4", "status_code": 503, "domain": "api.corp.come"},
    {"src_ip": "10.0.0.1", "status_code": 401, "domain": "login.corp.com"},

]

df = pd.DataFrame(logs)
failed = df[df["status_code"] == 401]
counts = df[df["status_code"] == 401].groupby("src_ip").size()
flagged = counts[counts > 1]
print("\n--- Failed Login Detection ---")
for ip, count in flagged.items():
    print(f"ALERT: {ip} had {count} failed login attempts")
    
