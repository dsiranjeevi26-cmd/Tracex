import json
from pathlib import Path
from datetime import datetime

from parser.parser import parse_logs
from alerts.alert_generator import create_alert


FAILED_THRESHOLD = 5
TIME_WINDOW = 60

BASE_DIR = Path(__file__).resolve().parent.parent


def main():

    print("""
========== TRACEX BRUTE-FORCE DETECTOR ==========
""")

    print(f"Detection threshold : {FAILED_THRESHOLD} failed attempts")
    print(f"Detection window    : {TIME_WINDOW} seconds")
    print()
    print("Analyzing local lab logs...")
    print()

    events = parse_logs()

    failed_events = [
        event for event in events
        if event.get("event_type") == "failed_login"
    ]

    groups = {}

    for event in failed_events:

        key = (
            event.get("username"),
            event.get("source_ip"),
            event.get("service")
        )

        groups.setdefault(key, []).append(event)

    new_alert_id = None

    for key, group in groups.items():

        if len(group) < FAILED_THRESHOLD:
            continue

        group.sort(
            key=lambda x: datetime.strptime(
                x["timestamp"],
                "%Y-%m-%d %H:%M:%S"
            )
        )

        for i in range(len(group)):

            window_events = []

            start_time = datetime.strptime(
                group[i]["timestamp"],
                "%Y-%m-%d %H:%M:%S"
            )

            for event in group[i:]:

                event_time = datetime.strptime(
                    event["timestamp"],
                    "%Y-%m-%d %H:%M:%S"
                )

                difference = (
                    event_time - start_time
                ).total_seconds()

                if difference <= TIME_WINDOW:
                    window_events.append(event)
                else:
                    break

            if len(window_events) >= FAILED_THRESHOLD:

                username, source_ip, service = key

                alert = create_alert(
                    rule="BRUTE_FORCE_AUTH",
                    severity="HIGH",
                    username=username,
                    source_ip=source_ip,
                    service=service,
                    attempts=len(window_events),
                    time_window=TIME_WINDOW,
                    reason="Multiple failed authentication attempts detected"
                )

                if alert:

                    new_alert_id = alert.get("alert_id")

                    print("🚨 NEW TRACEX ALERT")
                    print()
                    print(f"Alert ID      : {alert.get('alert_id')}")
                    print(f"Detection     : BRUTE_FORCE_AUTH")
                    print(f"Severity      : HIGH")
                    print(f"Username      : {username}")
                    print(f"Source IP     : {source_ip}")
                    print(f"Service       : {service}")
                    print(f"Attempts      : {len(window_events)}")
                    print(f"Time Window   : {TIME_WINDOW} seconds")

                else:

                    print("ℹ️ TRACEX DUPLICATE ALERT")
                    print(
                        "The same detection activity has already "
                        "generated an alert."
                    )

                break

    print("""
========== DETECTION COMPLETE ==========
""")

    # Save the newly created alert ID so tracex.py can use it.
    state_file = BASE_DIR / "alerts" / "latest_detection.json"

    state = {
        "new_alert_created": bool(new_alert_id),
        "alert_id": new_alert_id
    }

    with open(state_file, "w") as file:
        json.dump(state, file, indent=4)


if __name__ == "__main__":
    main()
