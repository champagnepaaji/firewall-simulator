from ips import record_violation, is_blocked
from packet import Packet
from rules import firewall_rules
from threat_intel import is_malicious
from metrics import record_decision, record_blocked_ip


def check_packet(packet):

    # 1️⃣ Threat-intel blocking
    if is_malicious(packet.src_ip):
        record_decision("DENY")              # 🔴 count a DENY
        record_blocked_ip(packet.src_ip)     # 🚫 show in dashboard
        record_violation(packet.src_ip)
        return "DENY"

    # 2️⃣ IPS auto-block check
    if is_blocked(packet.src_ip):
        record_decision("DENY")              # 🔴 count a DENY
        record_blocked_ip(packet.src_ip)
        return "DENY"

    # 3️⃣ Rule evaluation (priority-based)
    sorted_rules = sorted(
        firewall_rules,
        key=lambda r: r.get("priority", 100)
    )

    for rule in sorted_rules:

        # Source-IP rule
        if rule.get("src_ip") and packet.src_ip == rule["src_ip"]:
            record_decision(rule["action"])  # 🔵 ALLOW or DENY
            if rule["action"] == "DENY":
                record_violation(packet.src_ip)
            return rule["action"]

        # Protocol + Port rule
        if (
                rule.get("protocol")
                and rule.get("dst_port")
                and packet.protocol == rule["protocol"]
                and packet.dst_port == rule["dst_port"]
        ):
            record_decision(rule["action"])  # 🔵 ALLOW or DENY
            if rule["action"] == "DENY":
                record_violation(packet.src_ip)
            return rule["action"]

    # 4️⃣ Default deny
    record_decision("DENY")                  # 🔴 count a DENY
    record_violation(packet.src_ip)
    return "DENY"



def log_packet(packet, action):
    with open("logs.txt", "a", encoding="utf-8") as log:
        log.write(f"{packet.display()} -> {action}\n")


if __name__ == "__main__":
    packet1 = Packet("192.168.1.10", "10.0.0.5", 12345,80,"TCP")

    #call firewall decision
    decision = check_packet(packet1)
    #call logging (after decision)
    log_packet(packet1, decision)
    #result
    print(packet1.display())
    print("Firewall Decision:", decision)
