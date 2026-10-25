
def packet_matches(rule, packet):
    if not rule.enabled:
        return False

    if rule.source_ip not in ("*", packet["source_ip"]):
        return False

    if rule.destination_ip not in (
        "*",
        packet["destination_ip"],
    ):
        return False

    if rule.port is not None and rule.port != packet["port"]:
        return False

    if rule.protocol not in ("ANY", packet["protocol"].upper()):
        return False

    return True


def process_packet(packet, rules):
    ordered_rules = sorted(rules, key=lambda rule: rule.priority)

    for rule in ordered_rules:
        if packet_matches(rule, packet):
            return {
                "decision": rule.action,
                "matched_rule_id": rule.id,
                "matched_rule_name": rule.name,
                "reason": f"Matched firewall rule: {rule.name}",
            }

    return {
        "decision": "BLOCK",
        "matched_rule_id": None,
        "matched_rule_name": None,
        "reason": "No matching rule; default-deny policy",
    }
