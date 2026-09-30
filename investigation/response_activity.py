import json
import os
from datetime import datetime


CASES_FILE = "alerts/cases.json"


RESPONSE_ACTIONS = [
    "Validate Authentication",
    "Review Privileged Activity",
    "Verify Account Ownership",
    "Review Account Modification",
    "Escalate Case",
    "Containment Recommended",
    "Close Investigation"
]

ACTION_STATUSES = [
    "RECOMMENDED",
    "IN_PROGRESS",
    "COMPLETED",
    "SKIPPED"
]


def load_cases():
    if not os.path.exists(CASES_FILE):
        print("[!] cases.json not found.")
        return []

    try:
        with open(CASES_FILE, "r") as f:
            data = json.load(f)

        return data if isinstance(data, list) else []

    except json.JSONDecodeError:
        print("[!] Invalid cases.json.")
        return []


def save_cases(cases):
    with open(CASES_FILE, "w") as f:
        json.dump(cases, f, indent=4)


def select_case(cases):
    print("\n========== TRACEX RESPONSE ACTIVITY ==========\n")

    for case in cases:
        print(
            f"{case.get('case_id')} | "
            f"{case.get('username')} | "
            f"{case.get('source_ip')} | "
            f"{case.get('status')} | "
            f"Risk: {case.get('risk_score', 0)}/100 "
            f"{case.get('risk_level', 'UNKNOWN')}"
        )

    case_id = input("\nEnter Case ID: ").strip()

    for case in cases:
        if case.get("case_id") == case_id:
            return case

    print("[!] Case not found.")
    return None


def show_actions(case):
    actions = case.get("response_actions", [])

    print("\n========== RESPONSE ACTIONS ==========\n")

    if not actions:
        print("[!] No response actions recorded.")
        return

    for index, action in enumerate(actions, start=1):
        print(
            f"[{index}] "
            f"{action.get('action')} | "
            f"{action.get('status')} | "
            f"{action.get('timestamp')}"
        )

        if action.get("note"):
            print(f"    Note: {action.get('note')}")


def add_action(case):
    print("\n========== ADD RESPONSE ACTION ==========\n")

    for index, action in enumerate(RESPONSE_ACTIONS, start=1):
        print(f"{index}. {action}")

    try:
        choice = int(input("\nSelect action: ").strip())
    except ValueError:
        print("[!] Invalid selection.")
        return

    if choice < 1 or choice > len(RESPONSE_ACTIONS):
        print("[!] Invalid action.")
        return

    action_name = RESPONSE_ACTIONS[choice - 1]

    print("\nSelect status:")

    for index, status in enumerate(ACTION_STATUSES, start=1):
        print(f"{index}. {status}")

    try:
        status_choice = int(input("\nSelect status: ").strip())
    except ValueError:
        print("[!] Invalid selection.")
        return

    if status_choice < 1 or status_choice > len(ACTION_STATUSES):
        print("[!] Invalid status.")
        return

    action_status = ACTION_STATUSES[status_choice - 1]

    note = input("\nAnalyst note: ").strip()

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    action = {
        "action": action_name,
        "status": action_status,
        "timestamp": timestamp,
        "note": note
    }

    if "response_actions" not in case:
        case["response_actions"] = []

    case["response_actions"].append(action)

    case["updated_at"] = datetime.now().isoformat()

    save_cases(cases)

    print("\n[+] Response action saved.")
    print(f"    Action : {action_name}")
    print(f"    Status : {action_status}")


def update_action(case):
    actions = case.get("response_actions", [])

    if not actions:
        print("\n[!] No response actions available.")
        return

    print("\n========== UPDATE RESPONSE ACTION ==========\n")

    for index, action in enumerate(actions, start=1):
        print(
            f"{index}. "
            f"{action.get('action')} | "
            f"{action.get('status')}"
        )

    try:
        choice = int(input("\nSelect action: ").strip())
    except ValueError:
        print("[!] Invalid selection.")
        return

    if choice < 1 or choice > len(actions):
        print("[!] Invalid selection.")
        return

    selected = actions[choice - 1]

    print("\nNew status:")

    for index, status in enumerate(ACTION_STATUSES, start=1):
        print(f"{index}. {status}")

    try:
        status_choice = int(input("\nSelect status: ").strip())
    except ValueError:
        print("[!] Invalid status.")
        return

    if status_choice < 1 or status_choice > len(ACTION_STATUSES):
        print("[!] Invalid status.")
        return

    new_status = ACTION_STATUSES[status_choice - 1]

    old_status = selected.get("status")

    selected["status"] = new_status
    selected["updated_at"] = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    case["updated_at"] = datetime.now().isoformat()

    if "response_activity_history" not in case:
        case["response_activity_history"] = []

    case["response_activity_history"].append(
        {
            "timestamp": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "action": selected.get("action"),
            "from_status": old_status,
            "to_status": new_status
        }
    )

    save_cases(cases)

    print("\n[+] Response action updated.")
    print(f"    Action : {selected.get('action')}")
    print(f"    Status : {old_status} -> {new_status}")


def main():
    cases = load_cases()

    if not cases:
        print("[!] No cases available.")
        return

    case = select_case(cases)

    if not case:
        return

    while True:

        print("\n========== RESPONSE MENU ==========")
        print("1. View Response Actions")
        print("2. Add Response Action")
        print("3. Update Action Status")
        print("0. Exit")

        choice = input("\nSelect option: ").strip()

        if choice == "1":
            show_actions(case)

        elif choice == "2":
            add_action(case)

        elif choice == "3":
            update_action(case)

        elif choice == "0":
            print("\n[*] Exiting Response Activity.")
            break

        else:
            print("[!] Invalid option.")


if __name__ == "__main__":
    main()
