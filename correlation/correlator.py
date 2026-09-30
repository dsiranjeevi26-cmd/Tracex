import json
from pathlib import Path
from datetime import datetime

from parser.parser import parse_logs


BASE_DIR = Path(__file__).resolve().parent.parent

ALERT_FILE = (
    BASE_DIR
    / "alerts"
    / "alerts.json"
)

CORRELATION_FILE = (
    BASE_DIR
    / "alerts"
    / "correlation_results.json"
)


def load_alerts():

    try:

        with open(ALERT_FILE, "r") as file:

            data = json.load(file)

            if isinstance(data, list):
                return data

    except (
        FileNotFoundError,
        json.JSONDecodeError
    ):

        pass

    return []


def load_events():

    try:

        events = parse_logs()

        if isinstance(events, list):
            return events

    except Exception as error:

        print(
            f"[!] Parser error: {error}"
        )

    return []


def group_alerts(alerts):

    groups = {}

    for alert in alerts:

        username = alert.get(
            "username"
        )

        source_ip = alert.get(
            "source_ip"
        )

        if not username or not source_ip:
            continue

        # Correlate by identity and source,
        # rather than forcing every event
        # to have the same service field.

        key = (
            username,
            source_ip
        )

        groups.setdefault(
            key,
            []
        ).append(alert)

    return groups


def correlate_group(
    key,
    alerts,
    events
):

    username, source_ip = key

    related_events = []

    for event in events:

        if event.get(
            "username"
        ) != username:

            continue

        if event.get(
            "source_ip"
        ) != source_ip:

            continue

        related_events.append(
            event
        )

    related_events.sort(
        key=lambda event:
        datetime.strptime(
            event["timestamp"],
            "%Y-%m-%d %H:%M:%S"
        )
    )

    failed_logins = [
        event
        for event in related_events
        if event.get("event")
        == "Failed login"
    ]

    successful_logins = [
        event
        for event in related_events
        if event.get("event")
        == "Successful login"
    ]

    sudo_events = [
        event
        for event in related_events
        if event.get("event")
        == "Sudo command"
    ]

    account_changes = [
        event
        for event in related_events
        if event.get("event")
        == "Account change"
    ]

    detection_rules = sorted(
        set(
            alert.get(
                "detection_rule"
            )
            for alert in alerts
            if alert.get(
                "detection_rule"
            )
        )
    )

    services = sorted(
        set(
            alert.get(
                "service"
            )
            for alert in alerts
            if alert.get(
                "service"
            )
        )
    )

    correlation = {

        "username":
            username,

        "source_ip":
            source_ip,

        "service":
            services[0]
            if services
            else None,

        "alert_services":
            services,

        "related_alert_ids":
            [
                alert.get(
                    "alert_id"
                )
                for alert in alerts
                if alert.get(
                    "alert_id"
                )
            ],

        "detection_rules":
            detection_rules,

        "event_counts": {

            "failed_logins":
                len(
                    failed_logins
                ),

            "successful_logins":
                len(
                    successful_logins
                ),

            "sudo_events":
                len(
                    sudo_events
                ),

            "account_changes":
                len(
                    account_changes
                )
        },

        "timeline":
            related_events,

        "correlation_reason":
            (
                "Security alerts and related "
                "authentication, privilege, "
                "and account activity were "
                "correlated using common "
                "username and source IP."
            )
    }

    return correlation


def save_correlations(
    correlations
):

    CORRELATION_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        CORRELATION_FILE,
        "w"
    ) as file:

        json.dump(
            correlations,
            file,
            indent=4,
            default=str
        )

    print()

    print(
        f"[✓] Correlation results saved to: "
        f"{CORRELATION_FILE}"
    )


def display_correlation(
    correlation
):

    print()

    print("=" * 60)

    print(
        "          TRACEX MULTI-ALERT CORRELATION"
    )

    print("=" * 60)

    print()

    print(
        f"Username       : "
        f"{correlation['username']}"
    )

    print(
        f"Source IP      : "
        f"{correlation['source_ip']}"
    )

    print(
        f"Primary Service : "
        f"{correlation.get('service')}"
    )

    print(
        f"Alert Services : "
        f"{', '.join(correlation.get('alert_services', []))}"
    )

    print()

    print(
        "---------- RELATED ALERTS ----------"
    )

    for alert_id in correlation[
        "related_alert_ids"
    ]:

        print(
            f"  • {alert_id}"
        )

    print()

    print(
        "---------- DETECTION RULES ----------"
    )

    for rule in correlation[
        "detection_rules"
    ]:

        print(
            f"  • {rule}"
        )

    counts = correlation[
        "event_counts"
    ]

    print()

    print(
        "---------- CORRELATED EVIDENCE ----------"
    )

    print(
        f"Failed Logins      : "
        f"{counts['failed_logins']}"
    )

    print(
        f"Successful Logins  : "
        f"{counts['successful_logins']}"
    )

    print(
        f"Sudo Events        : "
        f"{counts['sudo_events']}"
    )

    print(
        f"Account Changes    : "
        f"{counts['account_changes']}"
    )

    print()

    print(
        "---------- TIMELINE ----------"
    )

    for event in correlation[
        "timeline"
    ]:

        print(
            f"{event['timestamp']} | "
            f"{event['event']}"
        )

    print()

    print(
        "---------- CORRELATION ASSESSMENT ----------"
    )

    print(
        "Related security activity was "
        "correlated using common username "
        "and source IP."
    )

    print(
        "Further investigation is required "
        "before confirming malicious activity."
    )

    print()

    print("=" * 60)


def main():

    print()

    print("=" * 60)

    print(
        "       TRACEX CORRELATION ENGINE"
    )

    print("=" * 60)

    alerts = load_alerts()

    events = load_events()

    if not alerts:

        print()

        print(
            "[i] No alerts available "
            "for correlation."
        )

        return

    if not events:

        print()

        print(
            "[i] No parsed events available."
        )

        return

    groups = group_alerts(
        alerts
    )

    correlations = []

    for key, group in groups.items():

        correlation = correlate_group(
            key,
            group,
            events
        )

        correlations.append(
            correlation
        )

    save_correlations(
        correlations
    )

    print()

    print(
        f"[+] Alerts loaded       : "
        f"{len(alerts)}"
    )

    print(
        f"[+] Parsed events       : "
        f"{len(events)}"
    )

    print(
        f"[+] Correlation groups  : "
        f"{len(correlations)}"
    )

    for correlation in correlations:

        display_correlation(
            correlation
        )

    print()

    print(
        "[✓] Correlation completed."
    )


if __name__ == "__main__":

    main()
