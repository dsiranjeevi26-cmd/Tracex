import json

ALERT_FILE = "alerts.json"


def load_alerts():
    try:
        with open(ALERT_FILE, "r") as file:
            return json.load(file)

    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_alerts(alerts):
    with open(ALERT_FILE, "w") as file:
        json.dump(alerts, file, indent=4)


def update_status(alert_id, new_status):

    allowed_statuses = [
        "NEW",
        "ACKNOWLEDGED",
        "INVESTIGATING",
        "RESOLVED"
    ]

    if new_status not in allowed_statuses:
        print("Invalid status.")
        return

    alerts = load_alerts()

    for alert in alerts:

        if alert["alert_id"] == alert_id:

            alert["status"] = new_status

            save_alerts(alerts)

            print(
                f"{alert_id} status updated to {new_status}"
            )

            return

    print(f"Alert {alert_id} not found.")
