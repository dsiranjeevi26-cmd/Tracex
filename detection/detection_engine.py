import json
from pathlib import Path
from datetime import datetime

from parser.parser import parse_logs
from alerts.alert_generator import create_alert


BASE_DIR = Path(__file__).resolve().parent.parent
STATE_FILE = BASE_DIR / "alerts" / "latest_detection.json"


FAILED_THRESHOLD = 5
TIME_WINDOW = 60


def save_detection_state(results):
    with open(STATE_FILE, "w") as file:
        json.dump(results, file, indent=4)


def parse_time(timestamp):
    return datetime.strptime(
        timestamp,
        "%Y-%m-%d %H:%M:%S"
    )


def detect_brute_force(events):

    failed = [
        event for event in events
        if event.get("event") == "Failed login"
    ]

    groups = {}

    for event in failed:

        key = (
            event.get("username"),
            event.get("source_ip"),
            event.get("service")
        )

        groups.setdefault(key, []).append(event)

    detections = []

    for key, group in groups.items():

        group.sort(
            key=lambda x: parse_time(x["timestamp"])
        )

        for i in range(len(group)):

            window = []

            start = parse_time(
                group[i]["timestamp"]
            )

            for event in group[i:]:

                current = parse_time(
                    event["timestamp"]
                )

                difference = (
                    current - start
                ).total_seconds()

                if difference <= TIME_WINDOW:
                    window.append(event)
                else:
                    break

            if len(window) >= FAILED_THRESHOLD:

                detections.append({
                    "rule": "BRUTE_FORCE_AUTH",
                    "severity": "HIGH",
                    "username": key[0],
                    "source_ip": key[1],
                    "service": key[2],
                    "attempts": len(window),
                    "time_window": TIME_WINDOW,
                    "reason":
                        "Multiple failed authentication attempts detected"
                })

                break

    return detections


def detect_success_after_failure(events):

    groups = {}

    for event in events:

        key = (
            event.get("username"),
            event.get("source_ip"),
            event.get("service")
        )

        groups.setdefault(key, []).append(event)

    detections = []

    for key, group in groups.items():

        group.sort(
            key=lambda x: parse_time(x["timestamp"])
        )

        failed_count = 0

        for event in group:

            event_type = event.get("event")

            if event_type == "Failed login":

                failed_count += 1

            elif (
                event_type == "Successful login"
                and failed_count > 0
            ):

                detections.append({
                    "rule": "SUCCESS_AFTER_FAILURE",
                    "severity": "HIGH",
                    "username": key[0],
                    "source_ip": key[1],
                    "service": key[2],
                    "attempts": failed_count,
                    "time_window": None,
                    "reason":
                        "Successful authentication observed after failed login activity"
                })

                break

    return detections


def detect_privileged_activity(events):

    detections = []

    for event in events:

        if event.get("event") != "Sudo command":
            continue

        detections.append({
            "rule": "PRIVILEGED_ACTIVITY",
            "severity": "MEDIUM",
            "username": event.get("username"),
            "source_ip": event.get("source_ip"),
            "service": "sudo",
            "attempts": 1,
            "time_window": None,
            "reason":
                "Privileged command activity observed"
        })

    return detections


def detect_account_modification(events):

    detections = []

    for event in events:

        if event.get("event") != "Account change":
            continue

        detections.append({
            "rule": "ACCOUNT_MODIFICATION",
            "severity": "HIGH",
            "username": event.get("username"),
            "source_ip": event.get("source_ip"),
            "service": "account",
            "attempts": 1,
            "time_window": None,
            "reason":
                "Account modification activity observed"
        })

    return detections


def create_alerts(detections):

    created_alerts = []

    for detection in detections:

        alert = create_alert(
            rule=detection["rule"],
            severity=detection["severity"],
            username=detection["username"],
            source_ip=detection["source_ip"],
            service=detection["service"],
            attempts=detection["attempts"],
            time_window=detection["time_window"],
            reason=detection["reason"]
        )

        if alert:

            alert_id = alert.get("alert_id")

            created_alerts.append(alert_id)

            print("\n🚨 NEW ALERT CREATED")

            print(f"Alert ID      : {alert_id}")
            print(f"Detection     : {detection['rule']}")
            print(f"Severity      : {detection['severity']}")
            print(f"Username      : {detection['username']}")
            print(f"Source IP     : {detection['source_ip']}")
            print(f"Reason        : {detection['reason']}")

        else:

            print(
                f"\nℹ️ Duplicate detection skipped: "
                f"{detection['rule']}"
            )

    return created_alerts


def main():

    print("""
============================================================
                 TRACEX DETECTION HUB
============================================================

Multiple security detection rules
""")

    events = parse_logs()

    print(
        f"Events analyzed : {len(events)}"
    )

    print("\nRunning detection rules...\n")

    all_detections = []

    # -------------------------------------------------------
    # RULE 1
    # -------------------------------------------------------

    brute_force = detect_brute_force(events)

    print(
        f"[1] BRUTE_FORCE_AUTH       : "
        f"{len(brute_force)} detection(s)"
    )

    all_detections.extend(brute_force)

    # -------------------------------------------------------
    # RULE 2
    # -------------------------------------------------------

    success_after_failure = detect_success_after_failure(
        events
    )

    print(
        f"[2] SUCCESS_AFTER_FAILURE  : "
        f"{len(success_after_failure)} detection(s)"
    )

    all_detections.extend(
        success_after_failure
    )

    # -------------------------------------------------------
    # RULE 3
    # -------------------------------------------------------

    privileged = detect_privileged_activity(
        events
    )

    print(
        f"[3] PRIVILEGED_ACTIVITY    : "
        f"{len(privileged)} detection(s)"
    )

    all_detections.extend(
        privileged
    )

    # -------------------------------------------------------
    # RULE 4
    # -------------------------------------------------------

    account_modification = detect_account_modification(
        events
    )

    print(
        f"[4] ACCOUNT_MODIFICATION   : "
        f"{len(account_modification)} detection(s)"
    )

    all_detections.extend(
        account_modification
    )

    # -------------------------------------------------------
    # CREATE ALERTS
    # -------------------------------------------------------

    print("\nCreating alerts...")

    created_alerts = create_alerts(
        all_detections
    )

    # -------------------------------------------------------
    # SAVE STATE
    # -------------------------------------------------------

    state = {
        "new_alert_created":
            len(created_alerts) > 0,

        "alert_ids":
            created_alerts,

        "detection_count":
            len(all_detections),

        "timestamp":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
    }

    save_detection_state(state)

    # -------------------------------------------------------
    # SUMMARY
    # -------------------------------------------------------

    print("""
============================================================
                 DETECTION SUMMARY
============================================================
""")

    print(
        f"Detection findings : "
        f"{len(all_detections)}"
    )

    print(
        f"New alerts         : "
        f"{len(created_alerts)}"
    )

    if created_alerts:

        print("\nNew Alert IDs:")

        for alert_id in created_alerts:
            print(f"  • {alert_id}")

    else:

        print("\nNo new alerts created.")

        print(
            "Existing detections were already processed."
        )

    print("""
============================================================
              DETECTION HUB COMPLETE
============================================================
""")


if __name__ == "__main__":
    main()

