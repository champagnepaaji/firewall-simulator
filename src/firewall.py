from rules import firewall_rules
from threat_intel import is_malicious_ip
from ips import record_violation, is_blocked
from logger import log_packet


def check_packet(packet):
    # 1️⃣ Threat intelligence check
    if is_malicious_ip(packet.src_ip):
        record_violation(packet.src_ip)
        log_packet(packet, "DENY", rule_id="THREAT_INTEL")
        return "DENY"

    # 2️⃣ IPS auto-block check
    if is_blocked(packet.src_ip):
        log_packet(packet, "DENY", rule_id="IPS_BLOCK")
        return "DENY"

    # 3️⃣ Firewall rules (priority-based)
    for rule in sorted(firewall_rules, key=lambda r: r["priority"]):

        # Source IP rule
        if rule.get("src_ip") and packet.src_ip == rule["src_ip"]:
            log_packet(packet, rule["action"], rule_id=rule["id"])
            return rule["action"]

        # Protocol + Port rule
        if (
                rule.get("protocol")
                and rule.get("dst_port")
                and packet.protocol == rule["protocol"]
                and packet.dst_port == rule["dst_port"]
        ):
            log_packet(packet, rule["action"], rule_id=rule["id"])
            return rule["action"]

    # 4️⃣ Default deny
    log_packet(packet, "DENY", rule_id="DEFAULT_DENY")
    return "DENY"
