from db import increment, get

# in-memory set (can be persisted later if needed)
blocked_ips = set()


def record_decision(decision):
    """
    Record ALLOW / DENY decisions persistently
    """
    increment(decision)


def record_blocked_ip(ip):
    """
    Track blocked IPs for dashboard visibility
    """
    blocked_ips.add(ip)


def get_metrics():
    return {
        "allow": get("ALLOW"),
        "deny": get("DENY"),
        "blocked_ips": list(blocked_ips)
    }
