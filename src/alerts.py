import json, os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ALERT_FILE = os.path.join(BASE_DIR, "alerts.json")

def load_alerts():
    if not os.path.exists(ALERT_FILE):
        return []
    with open(ALERT_FILE) as f:
        return json.load(f)

def save_alert(alert):
    alerts = load_alerts()
    alerts.append(alert)
    with open(ALERT_FILE, "w") as f:
        json.dump(alerts, f, indent=2)

def create_alert(message, severity):
    save_alert({
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "message": message,
        "severity": severity
    })


alerts =[]

def raise_alert(alert_type, src_ip, severity):
    alert = {
        "type": alert_type,
        "source": src_ip,
        "severity": severity

    }
    alerts.append(alert)
    print(f"🚨 ALERT [{severity}] {alert_type} from {src_ip}")
