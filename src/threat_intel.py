import ipaddress

# Simulated threat-intel feed
BLACKLISTED_NETWORKS = [
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("203.0.113.0/24")
]

def is_malicious(ip):
    ip_obj = ipaddress.ip_address(ip)
    return any(ip_obj in net for net in BLACKLISTED_NETWORKS)
