from rules import firewall_rules, increment_rule_hit
from threat_intel import is_malicious_ip
from ips import record_violation, is_blocked, record_request
from metrics import record_decision, record_blocked_ip
from logger import log_packet
from alerts import create_alert



def check_packet(packet):
    # Rate limiting / IPS abuse
    if record_request(packet.src_ip):
        record_decision("DENY")
        record_blocked_ip(packet.src_ip)
        create_alert(
            f"Rate limit exceeded by {packet.src_ip}",
            "HIGH"
        )
        log_packet(packet, "DENY", rule_id="RATE_LIMIT")
        return "DENY"

    # Threat intelligence
    if is_malicious_ip(packet.src_ip):
        record_violation(packet.src_ip)
        record_decision("DENY")
        record_blocked_ip(packet.src_ip)
        create_alert(
            f"Malicious IP detected: {packet.src_ip}",
            "HIGH"
        )
        log_packet(packet, "DENY", rule_id="THREAT_INTEL")
        return "DENY"

    # IPS auto-block
    if is_blocked(packet.src_ip):
        record_decision("DENY")
        record_blocked_ip(packet.src_ip)
        create_alert(
            f"IPS auto-block active for {packet.src_ip}",
            "MEDIUM"
        )
        log_packet(packet, "DENY", rule_id="IPS_BLOCK")
        return "DENY"

    # Firewall rules
    for rule in sorted(firewall_rules, key=lambda r: r["priority"]):

        if rule.get("src_ip") and packet.src_ip == rule["src_ip"]:
            increment_rule_hit(rule["id"])
            record_decision(rule["action"])
            log_packet(packet, rule["action"], rule_id=rule["id"])
            return rule["action"]

        if (
                rule.get("protocol")
                and rule.get("dst_port")
                and packet.protocol == rule["protocol"]
                and packet.dst_port == rule["dst_port"]
        ):
            increment_rule_hit(rule["id"])
            record_decision(rule["action"])
            log_packet(packet, rule["action"], rule_id=rule["id"])
            return rule["action"]

    # Default deny
    record_decision("DENY")
    log_packet(packet, "DENY", rule_id="DEFAULT_DENY")
    return "DENY"
