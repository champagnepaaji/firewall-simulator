
from collections import defaultdict
from alerts import raise_alert


scan_tracker = defaultdict(set)

def detect_port_scan(packet):
    scan_tracker[packet.src_ip].add(packet.dst_port)


    if len(scan_tracker[packet.src_ip]) > 5:
        raise_alert(
            alert_type="Port Scan",
            src_ip=packet.src_ip,
            severity="HIGH"
        )
        return True

    return False
