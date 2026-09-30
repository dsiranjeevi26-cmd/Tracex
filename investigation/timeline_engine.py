import json
import os


BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

CORRELATION_FILE = os.path.join(
    BASE_DIR,
    "alerts",
    "correlation_results.json"
)


def load_json(path):
    if not os.path.exists(path):
        return []

    try:
        with open(path, "r") as f:
            return json.load(f)

    except (json.JSONDecodeError, OSError):
        return []


def normalize_data(data):
    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        return [data]

    return []


def get_event_timestamp(event):

    if isinstance(event, dict):
        return event.get(
            "timestamp",
            ""
        )

    return ""


def get_event_name(event):

    if isinstance(event, dict):
        return str(
            event.get(
                "event",
                ""
            )
        ).strip()

    return ""


def classify_event(event):

    event_name = get_event_name(
        event
    ).lower()

    if event_name == "failed login":
        return "AUTH_FAILURE"

    if event_name == "successful login":
        return "AUTH_SUCCESS"

    if event_name == "sudo command":
        return "PRIVILEGED_ACTIVITY"

    if event_name == "account change":
        return "ACCOUNT_CHANGE"

    return "OTHER"


def event_description(event):

    if not isinstance(event, dict):
        return str(event)

    timestamp = event.get(
        "timestamp",
        ""
    )

    event_name = event.get(
        "event",
        "Unknown event"
    )

    username = event.get(
        "username"
    )

    source_ip = event.get(
        "source_ip"
    )

    service = event.get(
        "service"
    )

    command = event.get(
        "command"
    )

    action = event.get(
        "action"
    )

    description = (
        f"{timestamp} | "
        f"{event_name}"
    )

    if username:
        description += (
            f" | user={username}"
        )

    if source_ip:
        description += (
            f" | src_ip={source_ip}"
        )

    if service:
        description += (
            f" | service={service}"
        )

    if command:
        description += (
            f" | command={command}"
        )

    if action:
        description += (
            f" | action={action}"
        )

    return description


def build_timeline(correlation):

    raw_events = correlation.get(
        "timeline",
        []
    )

    timeline = []

    for event in raw_events:

        timeline.append(
            {
                "timestamp":
                    get_event_timestamp(
                        event
                    ),

                "category":
                    classify_event(
                        event
                    ),

                "description":
                    event_description(
                        event
                    )
            }
        )

    timeline.sort(
        key=lambda item:
        item["timestamp"]
    )

    return timeline


def print_event(
    index,
    event
):

    print(
        f"\n[{index}] "
        f"{event['timestamp']} "
        f"| {event['category']}"
    )

    print(
        f"    {event['description']}"
    )


def generate_assessment(
    timeline
):

    categories = [
        event["category"]
        for event in timeline
    ]

    failed = (
        "AUTH_FAILURE"
        in categories
    )

    success = (
        "AUTH_SUCCESS"
        in categories
    )

    privileged = (
        "PRIVILEGED_ACTIVITY"
        in categories
    )

    account_change = (
        "ACCOUNT_CHANGE"
        in categories
    )

    observations = []

    if failed:

        observations.append(
            "Authentication failures "
            "were observed."
        )

    if failed and success:

        observations.append(
            "A successful authentication "
            "occurred after authentication "
            "failures."
        )

    if privileged:

        observations.append(
            "Privileged activity was observed."
        )

    if account_change:

        observations.append(
            "An account modification event "
            "was observed."
        )

    if not observations:

        observations.append(
            "No significant investigation "
            "sequence was identified."
        )

    return observations


def investigate_correlation(
    correlation,
    index
):

    username = correlation.get(
        "username",
        "unknown"
    )

    source_ip = correlation.get(
        "source_ip",
        "unknown"
    )

    timeline = build_timeline(
        correlation
    )

    print("\n" + "=" * 70)

    print(
        f"       TRACEX INVESTIGATION TIMELINE "
        f"#{index}"
    )

    print("=" * 70)

    print(
        f"\nUsername  : {username}"
    )

    print(
        f"Source IP : {source_ip}"
    )

    print(
        f"Events    : {len(timeline)}"
    )

    print(
        "\n--- CHRONOLOGICAL EVENT TIMELINE ---"
    )

    if not timeline:

        print(
            "  No timeline events available."
        )

    else:

        for number, event in enumerate(
            timeline,
            start=1
        ):

            print_event(
                number,
                event
            )

    print(
        "\n--- INVESTIGATION OBSERVATIONS ---"
    )

    observations = generate_assessment(
        timeline
    )

    for observation in observations:

        print(
            f"  • {observation}"
        )

    print(
        "\n--- ANALYST INTERPRETATION ---"
    )

    print(
        "The timeline provides contextual "
        "evidence for analyst review. "
        "Event sequence alone does not "
        "confirm malicious activity."
    )

    print("=" * 70)


def main():

    data = load_json(
        CORRELATION_FILE
    )

    correlations = normalize_data(
        data
    )

    if not correlations:

        print(
            "[!] No correlation data found."
        )

        return

    print(
        "\nAvailable Investigation Groups:"
    )

    for index, correlation in enumerate(
        correlations,
        start=1
    ):

        timeline_count = len(
            correlation.get(
                "timeline",
                []
            )
        )

        print(
            f"  [{index}] "
            f"{correlation.get('username', 'unknown')} "
            f"| "
            f"{correlation.get('source_ip', 'unknown')} "
            f"| "
            f"{timeline_count} events"
        )

    choice = input(
        "\nSelect investigation group: "
    ).strip()

    try:

        selected = int(choice)

    except ValueError:

        print(
            "[!] Invalid selection."
        )

        return

    if (
        selected < 1
        or selected > len(correlations)
    ):

        print(
            "[!] Investigation group "
            "not found."
        )

        return

    investigate_correlation(
        correlations[selected - 1],
        selected
    )


if __name__ == "__main__":
    main()
