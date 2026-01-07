import json
import os

RULES_FILE = "rules.json"


def load_rules():
    if not os.path.exists(RULES_FILE):
        return []
    with open(RULES_FILE, "r") as f:
        return json.load(f)


def save_rules(rules):
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=2)


# Load rules at startup
firewall_rules = load_rules()


def add_rule(rule):
    firewall_rules.append(rule)
    save_rules(firewall_rules)


def delete_rule(rule_id):
    global firewall_rules
    firewall_rules = [r for r in firewall_rules if r["id"] != rule_id]
    save_rules(firewall_rules)


def get_rule(rule_id):
    for r in firewall_rules:
        if r["id"] == rule_id:
            return r
    return None


def update_rule(rule_id, updated_data):
    rule = get_rule(rule_id)
    if rule:
        rule.update(updated_data)
        save_rules(firewall_rules)
