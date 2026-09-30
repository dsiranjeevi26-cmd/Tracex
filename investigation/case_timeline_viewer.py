import json
from datetime import datetime


CASES_FILE = "alerts/cases.json"


def load_cases():
    try:
        with open(CASES_FILE, "r") as f:
            cases = json.load(f)

        if isinstance(cases, dict):
            cases = list(cases.values())

        return cases

    except (FileNotFoundError, json.JSONDecodeError):
        return []


def parse_timestamp(value):
    if not value:
        return datetime.min

    value = str(value)

    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f"
    ]

    for fmt in formats:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue

    return datetime.min


def select_case(cases):

    if not cases:
        print("\n[!] No cases available.")
        return None

    print("\n========== TRACEX CASES ==========")

    for case in cases:

        print(
            f"{case.get('case_id', 'N/A')} | "
            f"{case.get('username', 'N/A')} | "
            f"{case.get('source_ip', 'N/A')} | "
            f"Risk: {case.get('risk_score', 'N/A')}/100 | "
            f"Status: {case.get('status', 'N/A')}"
        )

    case_id = input(
        "\nEnter Case ID: "
    ).strip()

    for case in cases:

        if case.get("case_id") == case_id:
            return case

    print("[!] Case not found.")

    return None


def build_timeline(case):

    timeline = []

    # --------------------------------------------------------
    # CASE CREATED
    # --------------------------------------------------------

    if case.get("created_at"):

        timeline.append({

            "timestamp":
                case.get("created_at"),

            "category":
                "CASE",

            "event":
                "CASE_CREATED",

            "details":
                "Investigation case created"
        })

    # --------------------------------------------------------
    # STATUS HISTORY
    # --------------------------------------------------------

    for item in case.get(
        "status_history",
        []
    ):

        timeline.append({

            "timestamp":
                item.get("timestamp"),

            "category":
                "CASE_LIFECYCLE",

            "event":
                "STATUS_CHANGE",

            "details":
                f"{item.get('from_status', 'INITIAL')} "
                f"→ "
                f"{item.get('to_status', 'N/A')} "
                f"({item.get('reason', 'N/A')})"
        })

    # --------------------------------------------------------
    # ANALYST DECISIONS
    # --------------------------------------------------------

    for item in case.get(
        "decision_history",
        []
    ):

        timeline.append({

            "timestamp":
                item.get("timestamp"),

            "category":
                "ANALYST",

            "event":
                "ANALYST_DECISION",

            "details":
                item.get(
                    "decision",
                    "N/A"
                )
        })

    # --------------------------------------------------------
    # ANALYST NOTES
    # --------------------------------------------------------

    for item in case.get(
        "analyst_notes",
        []
    ):

        timeline.append({

            "timestamp":
                item.get("timestamp"),

            "category":
                "ANALYST",

            "event":
                "ANALYST_NOTE",

            "details":
                item.get(
                    "note",
                    "N/A"
                )
        })

    # --------------------------------------------------------
    # INVESTIGATION ACTIVITY
    # --------------------------------------------------------

    for item in case.get(
        "investigation_activity",
        []
    ):

        timeline.append({

            "timestamp":
                item.get("timestamp"),

            "category":
                "INVESTIGATION",

            "event":
                item.get(
                    "activity",
                    "INVESTIGATION_ACTIVITY"
                ),

            "details":
                item.get(
                    "description",
                    ""
                )
        })

    # --------------------------------------------------------
    # RESPONSE ACTIONS
    # --------------------------------------------------------

    for item in case.get(
        "response_actions",
        []
    ):

        timestamp = (
            item.get("created_at")
            or item.get("timestamp")
            or item.get("updated_at")
        )

        timeline.append({

            "timestamp":
                timestamp,

            "category":
                "RESPONSE",

            "event":
                "RESPONSE_ACTION",

            "details":
                f"{item.get('action', 'N/A')} "
                f"[{item.get('status', 'N/A')}]"
        })

    # --------------------------------------------------------
    # RESPONSE HISTORY
    # --------------------------------------------------------

    for item in case.get(
        "response_activity_history",
        []
    ):

        timeline.append({

            "timestamp":
                item.get("timestamp"),

            "category":
                "RESPONSE",

            "event":
                "RESPONSE_STATUS_CHANGE",

            "details":
                f"{item.get('action', 'N/A')} : "
                f"{item.get('from_status', 'NEW')} "
                f"→ "
                f"{item.get('to_status', 'N/A')}"
        })

    # --------------------------------------------------------
    # RESOLUTION
    # --------------------------------------------------------

    resolution = case.get(
        "resolution",
        {}
    )

    if resolution:

        timeline.append({

            "timestamp":
                resolution.get(
                    "resolved_at"
                ),

            "category":
                "CASE",

            "event":
                "CASE_RESOLUTION",

            "details":
                resolution.get(
                    "reason",
                    "Case resolved"
                )
        })

    # --------------------------------------------------------
    # REOPEN HISTORY
    # --------------------------------------------------------

    for item in case.get(
        "reopen_history",
        []
    ):

        timeline.append({

            "timestamp":
                item.get("timestamp"),

            "category":
                "CASE_LIFECYCLE",

            "event":
                "CASE_REOPENED",

            "details":
                item.get(
                    "reason",
                    "Case reopened"
                )
        })

    timeline.sort(
        key=lambda item:
            parse_timestamp(
                item.get("timestamp")
            )
    )

    return timeline


def display_timeline(case, timeline):

    print("\n")
    print("=" * 75)
    print("                 TRACEX CASE TIMELINE")
    print("=" * 75)

    print(
        f"\nCase ID    : "
        f"{case.get('case_id', 'N/A')}"
    )

    print(
        f"Username   : "
        f"{case.get('username', 'N/A')}"
    )

    print(
        f"Source IP  : "
        f"{case.get('source_ip', 'N/A')}"
    )

    print(
        f"Risk       : "
        f"{case.get('risk_score', 'N/A')}/100 "
        f"({case.get('risk_level', 'N/A')})"
    )

    print(
        f"Status     : "
        f"{case.get('status', 'N/A')}"
    )

    print("\n" + "-" * 75)

    if not timeline:

        print(
            "\n[!] No timeline events available."
        )

        return

    for index, item in enumerate(
        timeline,
        start=1
    ):

        print(
            f"\n[{index}] "
            f"{item.get('timestamp', 'N/A')}"
        )

        print(
            f"    Category : "
            f"{item.get('category', 'N/A')}"
        )

        print(
            f"    Event    : "
            f"{item.get('event', 'N/A')}"
        )

        print(
            f"    Details  : "
            f"{item.get('details', 'N/A')}"
        )

    print("\n" + "-" * 75)

    print(
        f"\nTotal Timeline Events: "
        f"{len(timeline)}"
    )

    print("=" * 75)


def main():

    print(
        "\n========== TRACEX TIMELINE ENGINE =========="
    )

    cases = load_cases()

    case = select_case(cases)

    if not case:
        return

    timeline = build_timeline(
        case
    )

    display_timeline(
        case,
        timeline
    )


if __name__ == "__main__":
    main()
