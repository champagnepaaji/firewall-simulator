from collections import defaultdict

# Track bad behavior per IP
violation_count = defaultdict(int)

# Block threshold
BLOCK_THRESHOLD = 3

# Auto-blocked IPs
blocked_ips = set()


def record_violation(src_ip):
    violation_count[src_ip] += 1

    if violation_count[src_ip] >= BLOCK_THRESHOLD:
        blocked_ips.add(src_ip)


def is_blocked(src_ip):
    return src_ip in blocked_ips
