

alerts =[]

def raise_alert(alert_type, src_ip, severity):
    alert = {
        "type": alert_type,
        "source": src_ip,
        "severity": severity

    }
    alerts.append(alert)
    print(f"🚨 ALERT [{severity}] {alert_type} from {src_ip}")
