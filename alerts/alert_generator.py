import json
from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
ALERT_FILE = BASE_DIR / "alerts" / "alerts.json"


def load_alerts():

    try:

        with open(ALERT_FILE, "r") as file:
            data = json.load(file)

            if isinstance(data, list):
                return data

            return []

    except (FileNotFoundError, json.JSONDecodeError):

        return []


def save_alerts(alerts):

    ALERT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(ALERT_FILE, "w") as file:

        json.dump(
            alerts,
            file,
            indent=4
        )


def generate_alert_id(alerts):

    numbers = []

    for alert in alerts:

        alert_id = alert.get("alert_id", "")

        if not alert_id.startswith("TRX-"):
            continue

        try:

            number = int(
                alert_id.replace("TRX-", "")
            )

            numbers.append(number)

        except ValueError:

            continue

    next_number = max(numbers, default=0) + 1

    return f"TRX-{next_number:04d}"


def generate_fingerprint(
    username,
    source_ip,
    service,
    detection_rule
):

    return (
        f"{detection_rule}|"
        f"{username}|"
        f"{source_ip}|"
        f"{service}"
    )


def alert_matches_activity(
    alert,
    username,
    source_ip,
    service,
    detection_rule
):

    fingerprint = generate_fingerprint(
        username,
        source_ip,
        service,
        detection_rule
    )

    if alert.get("fingerprint") == fingerprint:
        return True

    # Backward compatibility
    # for older alerts.

    return (
        alert.get("detection_rule") == detection_rule
        and alert.get("username") == username
        and alert.get("source_ip") == source_ip
        and alert.get("service") == service
    )


def alert_already_exists(
    alerts,
    username,
    source_ip,
    service,
    detection_rule
):

    for alert in alerts:

        if alert_matches_activity(
            alert,
            username,
            source_ip,
            service,
            detection_rule
        ):

            return True

    return False


def create_alert(
    username,
    source_ip,
    service,
    attempts=0,
    time_window=0,
    rule="BRUTE_FORCE_AUTH",
    severity="MEDIUM",
    reason="Suspicious security activity detected"
):

    alerts = load_alerts()

    # Check for duplicate activity.

    if alert_already_exists(
        alerts,
        username,
        source_ip,
        service,
        rule
    ):

        return None

    fingerprint = generate_fingerprint(
        username,
        source_ip,
        service,
        rule
    )

    alert = {

        "alert_id": generate_alert_id(alerts),

        "detection_rule": rule,

        "fingerprint": fingerprint,

        "severity": severity,

        "status": "NEW",

        "timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),

        "username": username,

        "source_ip": source_ip,

        "service": service,

        "attempt_count": attempts,

        "time_window": time_window,

        "reason": reason
    }

    alerts.append(alert)

    save_alerts(alerts)

    return alert
