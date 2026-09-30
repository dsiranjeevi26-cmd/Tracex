import json
import os
from datetime import datetime


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CASES_FILE = os.path.join(
    BASE_DIR,
    "alerts",
    "cases.json"
)


def load_cases():
    try:
        with open(CASES_FILE, "r") as file:
            data = json.load(file)

        if isinstance(data, list):
            return data

        if isinstance(data, dict) and isinstance(data.get("cases"), list):
            return data["cases"]

        if isinstance(data, dict):
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

    print("\n" + "=" * 60)
    print("              AVAILABLE CASES")
    print("=" * 60)

    for index, case in enumerate(cases, start=1):
        print(
            f"{index}. "
            f"{case.get('case_id', 'N/A')} | "
            f"{case.get('username', 'N/A')} | "
            f"{case.get('source_ip', 'N/A')} | "
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


def add_note(case, cases):
    print("\n" + "=" * 60)
    print("              ADD ANALYST NOTE")
    print("=" * 60)

    note = input("\nEnter analyst note: ").strip()

    if not note:
        print("\n[!] Note cannot be empty.")
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if "analyst_notes" not in case:
        case["analyst_notes"] = []

    case["analyst_notes"].append(
        {
            "timestamp": timestamp,
            "note": note
        }
    )

    save_cases(cases)

    print("\n[+] Analyst note saved.")
    print(f"Timestamp : {timestamp}")


def add_activity(case, cases):
    print("\n" + "=" * 60)
    print("          ADD INVESTIGATION ACTIVITY")
    print("=" * 60)

    print("\nExamples:")
    print("• Reviewed authentication timeline")
    print("• Validated source IP against available evidence")
    print("• Reviewed privileged activity")
    print("• Correlated account modification event")

    activity = input("\nEnter investigation activity: ").strip()

    if not activity:
        print("\n[!] Activity cannot be empty.")
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if "investigation_activity" not in case:
        case["investigation_activity"] = []

    case["investigation_activity"].append(
        {
            "timestamp": timestamp,
            "activity": activity
        }
    )

    save_cases(cases)

    print("\n[+] Investigation activity saved.")
    print(f"Timestamp : {timestamp}")


def view_history(case):
    print("\n" + "=" * 60)
    print("              CASE HISTORY")
    print("=" * 60)

    print(f"Case ID  : {case.get('case_id', 'N/A')}")
    print(f"Status   : {case.get('status', 'NEW')}")

    print("\n--- ANALYST NOTES ---")

    notes = case.get("analyst_notes", [])

    if notes:
        for note in notes:
            print(
                f"[{note.get('timestamp', 'N/A')}] "
                f"{note.get('note', '')}"
            )
    else:
        print("No analyst notes.")

    print("\n--- INVESTIGATION ACTIVITIES ---")

    activities = case.get("investigation_activity", [])

    if activities:
        for activity in activities:
            print(
                f"[{activity.get('timestamp', 'N/A')}] "
                f"{activity.get('activity', '')}"
            )
    else:
        print("No investigation activities.")

    print("\n--- DECISION HISTORY ---")

    decisions = case.get("decision_history", [])

    if decisions:
        for decision in decisions:
            print(
                f"[{decision.get('timestamp', 'N/A')}] "
                f"{decision.get('decision', 'N/A')}"
            )
    else:
        print("No decision history.")

    print("\n--- STATUS HISTORY ---")

    statuses = case.get("status_history", [])

    if statuses:
        for status in statuses:
            print(
                f"[{status.get('timestamp', 'N/A')}] "
                f"{status.get('from', 'N/A')} "
                f"→ "
                f"{status.get('to', 'N/A')} "
                f"({status.get('reason', 'N/A')})"
            )
    else:
        print("No status history.")


def main():

    print("\n" + "=" * 60)
    print("       TRACEX INVESTIGATION ACTIVITY ENGINE")
    print("=" * 60)

    cases = load_cases()

    print(f"\nCases loaded : {len(cases)}")

    case = select_case(cases)

    if not case:
        return

    while True:

        print("\n" + "=" * 60)
        print(
            f"CASE {case.get('case_id', 'N/A')} "
            f"| STATUS: {case.get('status', 'NEW')}"
        )
        print("=" * 60)

        print("\n1. Add Analyst Note")
        print("2. Add Investigation Activity")
        print("3. View Case History")
        print("0. Exit")

        choice = input("\nSelect option: ").strip()

        if choice == "1":
            add_note(case, cases)

        elif choice == "2":
            add_activity(case, cases)

        elif choice == "3":
            view_history(case)

        elif choice == "0":
            print("\n[+] Exiting investigation activity engine.")
            break

        else:
            print("\n[!] Invalid choice.")


if __name__ == "__main__":
    main()
