import json
import os
from datetime import datetime


CASES_FILE = "alerts/cases.json"


def load_cases():
    if not os.path.exists(CASES_FILE):
        print("[!] cases.json not found.")
        return []

    try:
        with open(CASES_FILE, "r") as f:
            data = json.load(f)

        if isinstance(data, list):
            return data

        return []

    except json.JSONDecodeError:
        print("[!] Invalid JSON in cases.json.")
        return []


def save_cases(cases):
    with open(CASES_FILE, "w") as f:
        json.dump(cases, f, indent=4)


def show_cases(cases):
    print("\n========== TRACEX CASE REOPEN ==========\n")

    if not cases:
        print("[!] No cases available.")
        return

    print("Available Cases:\n")

    for case in cases:
        print(
            f"{case.get('case_id')} | "
            f"{case.get('username')} | "
            f"{case.get('source_ip')} | "
            f"Status: {case.get('status')} | "
            f"Risk: {case.get('risk_score', 0)}/100 "
            f"{case.get('risk_level', 'UNKNOWN')}"
        )


def select_case(cases):
    case_id = input("\nEnter Case ID to reopen: ").strip()

    for case in cases:
        if case.get("case_id") == case_id:
            return case

    print("[!] Case not found.")
    return None


def show_case_details(case):
    print("\n========== CASE DETAILS ==========\n")

    print(f"Case ID       : {case.get('case_id')}")
    print(f"Username      : {case.get('username')}")
    print(f"Source IP     : {case.get('source_ip')}")
    print(f"Current Status: {case.get('status')}")
    print(
        f"Risk          : "
        f"{case.get('risk_score', 0)}/100 "
        f"{case.get('risk_level', 'UNKNOWN')}"
    )

    print(f"Related Alerts: {len(case.get('related_alert_ids', []))}")

    print(
        f"Previous Decisions: "
        f"{len(case.get('decision_history', []))}"
    )

    print(
        f"Previous Reopens: "
        f"{case.get('reopen_count', 0)}"
    )

    resolution = case.get("resolution")

    if resolution:
        print("\nPrevious Resolution:")
        print(f"Reason    : {resolution.get('reason')}")
        print(f"Timestamp : {resolution.get('timestamp')}")

    notes = case.get("analyst_notes", [])

    print(f"\nAnalyst Notes: {len(notes)}")

    for note in notes:
        print(
            f"  - {note.get('timestamp')} : "
            f"{note.get('note')}"
        )


def reopen_case(case):
    current_status = case.get("status")

    if current_status != "RESOLVED":
        print(
            f"\n[!] Case cannot be reopened."
            f"\n    Current status: {current_status}"
        )
        print("    Only RESOLVED cases can be reopened.")
        return False

    print("\n========== REOPEN VALIDATION ==========\n")

    resolution = case.get("resolution")

    if not resolution:
        print("[!] Previous resolution information is missing.")
        print("[!] Reopening blocked.")
        return False

    print("Previous resolution found.")
    print(f"Reason    : {resolution.get('reason')}")
    print(f"Timestamp : {resolution.get('timestamp')}")

    print("\nWhy is this case being reopened?")
    reason = input("> ").strip()

    if not reason:
        print("[!] Reopen reason cannot be empty.")
        return False

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    previous_status = case.get("status")

    case["status"] = "INVESTIGATING"
    case["updated_at"] = datetime.now().isoformat()

    case["reopened_at"] = timestamp

    case["reopen_count"] = case.get("reopen_count", 0) + 1

    reopen_entry = {
        "timestamp": timestamp,
        "previous_status": previous_status,
        "new_status": "INVESTIGATING",
        "reason": reason
    }

    if "reopen_history" not in case:
        case["reopen_history"] = []

    case["reopen_history"].append(reopen_entry)

    if "status_history" not in case:
        case["status_history"] = []

    case["status_history"].append(
        {
            "timestamp": timestamp,
            "from": previous_status,
            "to": "INVESTIGATING",
            "reason": "CASE_REOPENED"
        }
    )

    if "investigation_activity" not in case:
        case["investigation_activity"] = []

    case["investigation_activity"].append(
        {
            "timestamp": timestamp,
            "activity": f"Case reopened: {reason}"
        }
    )

    save_cases(cases)

    print("\n[+] CASE REOPENED SUCCESSFULLY")
    print(f"    Case ID : {case.get('case_id')}")
    print(f"    Status  : {case.get('status')}")
    print(f"    Reason  : {reason}")
    print(f"    Reopen # : {case.get('reopen_count')}")

    return True


def main():
    cases = load_cases()

    if not cases:
        return

    show_cases(cases)

    case = select_case(cases)

    if not case:
        return

    show_case_details(case)

    print("\n1. Reopen Case")
    print("0. Cancel")

    choice = input("\nSelect option: ").strip()

    if choice == "1":
        reopen_case(case)

    elif choice == "0":
        print("\n[*] Operation cancelled.")

    else:
        print("\n[!] Invalid option.")


if __name__ == "__main__":
    main()
