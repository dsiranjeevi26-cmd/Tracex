import json
import re
from datetime import datetime


ALERT_FILE = "alerts/alerts.json"
LOG_FILE = "logs/auth.log"


def load_alerts():
    try:
        with open(ALERT_FILE, "r") as file:
            return json.load(file)

    except (FileNotFoundError, json.JSONDecodeError):
        return []


def load_log_events():
    events = []

    pattern = re.compile(
        r"(?P<timestamp>\S+ \S+) "
        r"(?P<event>Failed login) "
        r"user=(?P<username>\S+) "
        r"src_ip=(?P<source_ip>\S+) "
        r"service=(?P<service>\S+)"
    )

    try:
        with open(LOG_FILE, "r") as file:

            for line in file:

                line = line.strip()

                match = pattern.match(line)

                if match:
                    events.append(match.groupdict())

    except FileNotFoundError:
        print("Log file not found.")

    return events


def investigate_alert(alert_id):

    alerts = load_alerts()

    selected_alert = None

    for alert in alerts:

        if alert["alert_id"] == alert_id:
            selected_alert = alert
            break

    if selected_alert is None:

        print(f"\nAlert {alert_id} not found.")
        return

    username = selected_alert["username"]
    source_ip = selected_alert["source_ip"]
    service = selected_alert["service"]

    events = load_log_events()

    related_events = []

    for event in events:

        if (
            event["username"] == username
            and event["source_ip"] == source_ip
            and event["service"] == service
        ):
            related_events.append(event)

    print("\n========== TRACEX INVESTIGATION ==========\n")

    print(f"Alert ID       : {selected_alert['alert_id']}")
    print(f"Detection Rule : {selected_alert['detection_rule']}")
    print(f"Severity       : {selected_alert['severity']}")
    print(f"Status         : {selected_alert['status']}")

    print("\n--------------- ALERT DETAILS ---------------\n")

    print(f"Affected User  : {username}")
    print(f"Source IP      : {source_ip}")
    print(f"Service        : {service}")
    print(f"Attempts       : {selected_alert['attempt_count']}")
    print(f"Time Window    : {selected_alert['time_window']} seconds")

    print("\n--------------- RELATED EVENTS ---------------\n")

    if not related_events:

        print("No related events found.")

    else:

        for event in related_events:

            print(
                f"{event['timestamp']} | "
                f"{event['event']} | "
                f"user={event['username']} | "
                f"src_ip={event['source_ip']} | "
                f"service={event['service']}"
            )

    print("\n--------------- INVESTIGATION SUMMARY ---------------\n")

    if related_events:

        first_time = datetime.strptime(
            related_events[0]["timestamp"],
            "%Y-%m-%d %H:%M:%S"
        )

        last_time = datetime.strptime(
            related_events[-1]["timestamp"],
            "%Y-%m-%d %H:%M:%S"
        )

        duration = (
            last_time - first_time
        ).total_seconds()

        print(
            f"{len(related_events)} failed authentication "
            f"attempts observed within {duration:.0f} seconds."
        )

    print("\n--------------- ANALYST ASSESSMENT ---------------\n")

    print("Investigation required.")
    print("Suspicious authentication activity detected.")
    print("No malicious activity confirmed by this detection alone.")

    print("\n===============================================\n")


def main():

    print("\n========== TRACEX INVESTIGATION ==========\n")

    alert_id = input(
        "Enter Alert ID to investigate: "
    ).strip()

    investigate_alert(alert_id)


if __name__ == "__main__":
    main()
