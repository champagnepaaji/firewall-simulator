import time

REQUEST_LIMIT = 5
WINDOW = 10  # seconds

requests = {}
blocked_ips = set()
violations = {}


def record_request(ip):
    now = time.time()
    requests.setdefault(ip, [])
    requests[ip] = [t for t in requests[ip] if now - t < WINDOW]
    requests[ip].append(now)

    if len(requests[ip]) > REQUEST_LIMIT:
        blocked_ips.add(ip)
        record_violation(ip)
        return True
    return False


def record_violation(ip):
    violations[ip] = violations.get(ip, 0) + 1


def is_blocked(ip):
    return ip in blocked_ips


def get_violations():
    return violations
