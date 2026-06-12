import re
from collections import defaultdict

logs = [
    '192.168.1.1 - - [15/Jan/2024:08:00:01] "GET /login HTTP/1.1" 200 1024',
    '192.168.1.1 - - [15/Jan/2024:08:00:02] "GET /login HTTP/1.1" 200 1024',
    '192.168.1.1 - - [15/Jan/2024:08:00:03] "GET /login HTTP/1.1" 200 1024',
    '192.168.1.1 - - [15/Jan/2024:08:00:04] "GET /login HTTP/1.1" 200 1024',
    '192.168.1.1 - - [15/Jan/2024:08:00:05] "GET /login HTTP/1.1" 200 1024',
    '10.0.0.5 - - [15/Jan/2024:08:01:00] "GET /home HTTP/1.1" 200 2048',
    '10.0.0.5 - - [15/Jan/2024:08:01:30] "GET /profile HTTP/1.1" 200 512',
    '192.168.1.2 - - [15/Jan/2024:08:02:00] "GET /login HTTP/1.1" 401 256',
    '192.168.1.2 - - [15/Jan/2024:08:02:01] "GET /login HTTP/1.1" 401 256',
    '192.168.1.2 - - [15/Jan/2024:08:02:02] "GET /login HTTP/1.1" 401 256',
    '192.168.1.2 - - [15/Jan/2024:08:02:03] "GET /login HTTP/1.1" 401 256',
    '192.168.1.2 - - [15/Jan/2024:08:02:04] "GET /login HTTP/1.1" 401 256',
    '192.168.1.2 - - [15/Jan/2024:08:02:05] "GET /login HTTP/1.1" 401 256',
    '10.0.0.9 - - [15/Jan/2024:08:03:00] "GET /home HTTP/1.1" 200 2048',
]

# Regex to parse each log line
pattern = re.compile(
    r'(?P<ip>\S+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) (?P<bytes>\d+)'
)

# Count 401s per IP on the login endpoint
failed_logins = defaultdict(int)

for line in logs:
    match = pattern.match(line)
    if not match:
        continue

    ip = match.group("ip")
    path = match.group("path")
    status = int(match.group("status"))

    if path == "/login" and status == 401:
        failed_logins[ip] += 1

# Flag IPs with more than 4 failed attempts
for ip, count in failed_logins.items():
    if count > 4:
        print(f"ALERT: {ip} had {count} failed login attempts against /login")