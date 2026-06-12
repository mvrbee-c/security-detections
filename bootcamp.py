src_ip = "10.10.10.10"
status_code = 200
is_suspicious = True
domain = "sample.com"
failed_ips = ["192.168.1.1", "10.0.0.5", "172.16.0.3"]
log_entry = {
    "src_ip": "10.5.6.7",
    "timestamp": "June 12, 2026 15:00",
    "status_code": 503,
    "domain": "test.com",
    "is_suspicious": True
}
logs = [
    {"src_ip": "10.0.0.1", "status_code": 401, "domain": "login.corp.com"},
    {"src_ip": "10.0.0.2", "status_code": 200, "domain": "home.corp.com"},
    {"src_ip": "10.0.0.3", "status_code": 403, "domain": "admin.corp.com"},
    {"src_ip": "10.0.0.4", "status_code": 503, "domain": "api.corp.com"},
    {"src_ip": "10.0.0.1", "status_code": 401, "domain": "login.corp.com"},
]

def check_status(status_code): 
    if status_code == 401:
        return "Failed authentication detected"
    elif status_code == 403:
        return "Access forbidden"
    elif status_code == 503:
        return "Service unavailable"
    else:
        return "Status normal"

print(check_status(log_entry["status_code"]))
print(f"Source IP: {src_ip} | Status Code: {status_code} | Suspicious: {is_suspicious} |  Domain: {domain}")

for entry in logs:
    print(f"Source IP: {entry['src_ip']} | Domain: {entry['domain']} |", check_status(entry['status_code']))


