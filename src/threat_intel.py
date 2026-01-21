import ipaddress


MALICIOUS_IPS = {
    "198.18.0.50",
    "198.19.255.200",
    "203.0.113.10"
}


def is_malicious_ip(ip):
    return ip in MALICIOUS_IPS

