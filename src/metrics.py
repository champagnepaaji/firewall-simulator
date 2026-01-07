stats = {
    "ALLOW": 0,
    "DENY": 0
}

blocked_ips = set()

def record_decision(action):
    if action in stats:
        stats[action] += 1

def record_blocked_ip(ip):
    blocked_ips.add(ip)
