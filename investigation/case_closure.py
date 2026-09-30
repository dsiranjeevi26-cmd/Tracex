import json
import os
from datetime import datetime


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CASES_FILE = os.path.join(
    BASE_DIR,
    "alerts",
    "cases.json"
)


VALID_STATUSES = {
    "NEW",
    "ACKNOWLEDGED",
    "INVESTIGATING",
    "RESOLVED"
}


def load_cases():
    try:
        with open(CASES_FILE, "r") as file:
            data = json.load(file)

        if isinstance(data, list):
            return data

        if isinstance(data, dict):
            if isinstance(data.get("cases"), list):
                return data["cases"]

            return [data]

        return []

    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_cases(cases):
    with open(CASES_FILE, "w") as file:
        json.dump(cases, file, indent=4)


def select_case(cases):

    if not cases:
        print("\n[!] No cases available.")
        return None

    print("\n" + "=" * 70)
    print("                    AVAILABLE CASES")
    print("=" * 70)

    for index, case in enumerate(cases, start=1):

        print(
            f"{index}. "
            f"{case.get('case_id', 'N/A')} | "
            f"{case.get('username', 'N/A')} | "
            f"{case.get('source_ip', 'N/A')} | "
            f"Risk: {case.get('risk_score', 0)}/100 "
            f"{case.get('risk_level', 'UNKNOWN')} | "
            f"Status: {case.get('status', 'NEW')}"
        )

    choice = input("\nSelect case: ").strip()

    try:

        index = int(choice) - 1

        if 0 <= index < len(cases):
            return cases[index]

    except ValueError:
        pass

    print("\n[!] Invalid case selection.")
    return None


def show_closure_evidence(case):

    print("\n" + "=" * 70)
    print("                 CASE CLOSURE REVIEW")
    print("=" * 70)

    print(f"\nCase ID       : {case.get('case_id', 'N/A')}")
    print(f"Current Status: {case.get('status', 'NEW')}")
    print(
        f"Risk          : "
        f"{case.get('risk_score', 0)}/100 "
        f"{case.get('risk_level', 'UNKNOWN')}"
    )

    print("\n--- ANALYST DECISION ---")

    print(
        f"Decision      : "
        f"{case.get('analyst_decision', 'NOT RECORDED')}"
    )

    print("\n--- ANALYST NOTES ---")

    notes = case.get("analyst_notes", [])

    if notes:

        for note in notes:
            print(
                f"• [{note.get('timestamp', 'N/A')}] "
                f"{note.get('note', '')}"
            )

    else:

        print("No analyst notes recorded.")

    print("\n--- INVESTIGATION ACTIVITIES ---")

    activities = case.get(
        "investigation_activity",
        []
    )

    if activities:

        for activity in activities:
            print(
                f"• [{activity.get('timestamp', 'N/A')}] "
                f"{activity.get('activity', '')}"
            )

    else:

        print("No investigation activities recorded.")

    print("\n--- MITRE EVIDENCE ---")

    mitre = case.get(
        "mitre_evidence",
        []
    )

    if mitre:

        for mapping in mitre:

            print(
                f"• {mapping.get('technique_id', 'N/A')} "
                f"- {mapping.get('technique_name', 'N/A')} "
                f"(events: {mapping.get('event_count', 0)})"
            )

    else:

        print("No MITRE evidence linked.")


def validate_resolution(case):

    print("\n" + "-" * 70)
    print("RESOLUTION VALIDATION")
    print("-" * 70)

    decision = case.get(
        "analyst_decision"
    )

    notes = case.get(
        "analyst_notes",
        []
    )

    activities = case.get(
        "investigation_activity",
        []
    )

    if decision != "RESOLVE":

        print(
            "\n[!] Resolution blocked."
        )

        print(
            "Reason: Analyst decision is not RESOLVE."
        )

        print(
            f"Current decision: "
            f"{decision or 'NOT RECORDED'}"
        )

        return False

    if not notes:

        print(
            "\n[!] Resolution blocked."
        )

        print(
            "Reason: At least one analyst note "
            "is required before closure."
        )

        return False

    if not activities:

        print(
            "\n[!] Resolution blocked."
        )

        print(
            "Reason: At least one investigation "
            "activity is required before closure."
        )

        return False

    print(
        "\n[✓] Resolution requirements satisfied."
    )

    print(
        "[✓] Analyst decision: RESOLVE"
    )

    print(
        f"[✓] Analyst notes: {len(notes)}"
    )

    print(
        f"[✓] Investigation activities: "
        f"{len(activities)}"
    )

    return True


def close_case(case, cases):

    if not validate_resolution(case):
        return

    print("\n" + "-" * 70)
    print("FINAL RESOLUTION")
    print("-" * 70)

    reason = input(
        "\nEnter resolution reason: "
    ).strip()

    if not reason:

        print(
            "\n[!] Resolution reason cannot be empty."
        )

        return

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    old_status = case.get(
        "status",
        "NEW"
    )

    case["status"] = "RESOLVED"

    case["resolution"] = {
        "reason": reason,
        "timestamp": timestamp
    }

    case["resolved_at"] = timestamp

    if "status_history" not in case:
        case["status_history"] = []

    case["status_history"].append(
        {
            "from": old_status,
            "to": "RESOLVED",
            "timestamp": timestamp,
            "reason": "CASE_RESOLUTION"
        }
    )

    save_cases(cases)

    print("\n" + "=" * 70)
    print("                 CASE RESOLVED")
    print("=" * 70)

    print(f"\nCase ID       : {case.get('case_id')}")
    print(f"Previous Status: {old_status}")
    print("Current Status : RESOLVED")
    print(f"Resolved At    : {timestamp}")
    print(f"Reason         : {reason}")

    print(
        "\n[+] Resolution persisted to cases.json"
    )


def main():

    print("\n" + "=" * 70)
    print("          TRACEX CASE CLOSURE ENGINE")
    print("=" * 70)

    cases = load_cases()

    print(
        f"\nCases loaded : {len(cases)}"
    )

    case = select_case(cases)

    if not case:
        return

    show_closure_evidence(case)

    print("\n" + "-" * 70)
    print("OPTIONS")
    print("-" * 70)

    print("1. Validate and Resolve Case")
    print("0. Cancel")

    choice = input(
        "\nSelect option: "
    ).strip()

    if choice == "1":

        close_case(
            case,
            cases
        )

    elif choice == "0":

        print(
            "\n[+] Closure cancelled."
        )

    else:

        print(
            "\n[!] Invalid choice."
        )


if __name__ == "__main__":
    main()
