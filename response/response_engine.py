import json
from pathlib import Path
from datetime import datetime


BASE_DIR = Path(__file__).resolve().parent.parent

CASES_FILE = (
    BASE_DIR
    / "alerts"
    / "cases.json"
)


CASE_STATUSES = [
    "NEW",
    "ACKNOWLEDGED",
    "INVESTIGATING",
    "RESOLVED"
]


ACTION_STATUSES = [
    "RECOMMENDED",
    "IN_PROGRESS",
    "COMPLETED",
    "SKIPPED"
]


RESPONSE_ACTIONS = [
    "Validate Authentication",
    "Review Privileged Activity",
    "Verify Account Ownership",
    "Review Account Modification",
    "Escalate Case",
    "Containment Recommended",
    "Close Investigation"
]


def load_cases():

    try:

        with open(CASES_FILE, "r") as file:

            data = json.load(file)

            if isinstance(data, list):
                return data

    except (
        FileNotFoundError,
        json.JSONDecodeError
    ):

        pass

    return []


def save_cases(cases):

    CASES_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(CASES_FILE, "w") as file:

        json.dump(
            cases,
            file,
            indent=4,
            default=str
        )


def find_case(cases, case_id):

    for case in cases:

        if case.get("case_id") == case_id:

            return case

    return None


def update_timestamp(case):

    case["updated_at"] = (
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )


def initialize_response_actions(case):

    if "response_actions" not in case:

        case["response_actions"] = []


def initialize_notes(case):

    if "analyst_notes" not in case:

        case["analyst_notes"] = []


def action_already_exists(
    case,
    action_name
):

    initialize_response_actions(case)

    for action in case["response_actions"]:

        if action.get("action") == action_name:

            return True

    return False


def add_response_action(
    case,
    action_name
):

    initialize_response_actions(case)

    if action_name not in RESPONSE_ACTIONS:

        print()
        print(
            "[!] Invalid response action."
        )

        return False

    if action_already_exists(
        case,
        action_name
    ):

        print()
        print(
            "[i] This response action "
            "already exists for the case."
        )

        return False

    action = {

        "action": action_name,

        "status": "RECOMMENDED",

        "created_at":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

        "updated_at":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
    }

    case["response_actions"].append(
        action
    )

    update_timestamp(case)

    return True


def update_action_status(
    case,
    action_number,
    new_status
):

    initialize_response_actions(case)

    if new_status not in ACTION_STATUSES:

        print()
        print(
            "[!] Invalid action status."
        )

        return False

    actions = case["response_actions"]

    if (
        action_number < 1
        or action_number > len(actions)
    ):

        print()
        print(
            "[!] Invalid action number."
        )

        return False

    action = actions[
        action_number - 1
    ]

    action["status"] = new_status

    action["updated_at"] = (
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )

    update_timestamp(case)

    return True


def update_case_status(
    case,
    new_status
):

    if new_status not in CASE_STATUSES:

        print()
        print(
            "[!] Invalid case status."
        )

        return False

    case["status"] = new_status

    update_timestamp(case)

    return True


def add_analyst_note(
    case,
    note
):

    initialize_notes(case)

    if not note.strip():

        print()
        print(
            "[!] Analyst note cannot be empty."
        )

        return False

    analyst_note = {

        "timestamp":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

        "note":
            note.strip()
    }

    case["analyst_notes"].append(
        analyst_note
    )

    update_timestamp(case)

    return True


def display_case(case):

    print()
    print("=" * 70)
    print("             TRACEX RESPONSE WORKFLOW")
    print("=" * 70)

    print()

    print(
        f"Case ID        : "
        f"{case.get('case_id')}"
    )

    print(
        f"Status         : "
        f"{case.get('status')}"
    )

    print(
        f"Username       : "
        f"{case.get('username')}"
    )

    print(
        f"Source IP      : "
        f"{case.get('source_ip')}"
    )

    print(
        f"Service        : "
        f"{case.get('service')}"
    )

    print()

    print("---------- RISK ----------")

    print(
        f"Risk Score     : "
        f"{case.get('risk_score', 0)}/100"
    )

    print(
        f"Risk Level     : "
        f"{case.get('risk_level', 'N/A')}"
    )

    print()

    print("---------- MITRE ATT&CK ----------")

    mappings = case.get(
        "mitre_mappings",
        []
    )

    if mappings:

        for mapping in mappings:

            print(
                f"  • "
                f"{mapping.get('technique_id')} - "
                f"{mapping.get('technique_name')}"
            )

    else:

        print(
            "  No MITRE mappings available."
        )

    print()

    print("---------- RESPONSE ACTIONS ----------")

    initialize_response_actions(case)

    actions = case["response_actions"]

    if not actions:

        print(
            "  No response actions added."
        )

    else:

        for index, action in enumerate(
            actions,
            start=1
        ):

            print(
                f"  [{index}] "
                f"{action.get('action')}"
            )

            print(
                f"      Status : "
                f"{action.get('status')}"
            )

    print()

    print("---------- ANALYST NOTES ----------")

    initialize_notes(case)

    notes = case["analyst_notes"]

    if not notes:

        print(
            "  No analyst notes."
        )

    else:

        for note in notes:

            print(
                f"  • "
                f"{note.get('timestamp')}"
            )

            print(
                f"    {note.get('note')}"
            )

    print()

    print("=" * 70)


def select_case(cases):

    print()

    print("Available Cases:")

    for case in cases:

        print(
            f"  {case.get('case_id')} "
            f"| Status: "
            f"{case.get('status')} "
            f"| Risk: "
            f"{case.get('risk_level', 'N/A')}"
        )

    print()

    case_id = input(
        "Enter Case ID: "
    ).strip()

    case = find_case(
        cases,
        case_id
    )

    if not case:

        print()
        print(
            "[!] Case not found."
        )

        return None

    return case


def show_response_actions(case):

    initialize_response_actions(case)

    actions = case["response_actions"]

    print()

    print(
        "========== RESPONSE ACTIONS =========="
    )

    if not actions:

        print(
            "No response actions available."
        )

        return

    for index, action in enumerate(
        actions,
        start=1
    ):

        print(
            f"[{index}] "
            f"{action.get('action')}"
        )

        print(
            f"    Status: "
            f"{action.get('status')}"
        )

        print(
            f"    Updated: "
            f"{action.get('updated_at')}"
        )


def add_action_console(case):

    print()

    print(
        "========== AVAILABLE RESPONSE ACTIONS =========="
    )

    for index, action in enumerate(
        RESPONSE_ACTIONS,
        start=1
    ):

        print(
            f"[{index}] {action}"
        )

    print()

    try:

        choice = int(
            input(
                "Select action number: "
            )
        )

    except ValueError:

        print()
        print(
            "[!] Enter a valid number."
        )

        return

    if (
        choice < 1
        or choice > len(RESPONSE_ACTIONS)
    ):

        print()
        print(
            "[!] Invalid action number."
        )

        return

    action_name = RESPONSE_ACTIONS[
        choice - 1
    ]

    if add_response_action(
        case,
        action_name
    ):

        print()
        print(
            "[✓] Response action added."
        )

    else:

        print()
        print(
            "[i] Response action was not added."
        )


def update_action_console(case):

    initialize_response_actions(case)

    actions = case["response_actions"]

    if not actions:

        print()
        print(
            "[i] No response actions available."
        )

        return

    show_response_actions(case)

    print()

    try:

        action_number = int(
            input(
                "Select action number: "
            )
        )

    except ValueError:

        print()
        print(
            "[!] Enter a valid number."
        )

        return

    print()

    print(
        "Available statuses:"
    )

    for index, status in enumerate(
        ACTION_STATUSES,
        start=1
    ):

        print(
            f"[{index}] {status}"
        )

    print()

    try:

        status_number = int(
            input(
                "Select status number: "
            )
        )

    except ValueError:

        print()
        print(
            "[!] Enter a valid number."
        )

        return

    if (
        status_number < 1
        or status_number > len(ACTION_STATUSES)
    ):

        print()
        print(
            "[!] Invalid status."
        )

        return

    new_status = ACTION_STATUSES[
        status_number - 1
    ]

    if update_action_status(
        case,
        action_number,
        new_status
    ):

        print()
        print(
            "[✓] Response action status updated."
        )


def update_case_status_console(case):

    print()

    print(
        "========== CASE STATUS =========="
    )

    for index, status in enumerate(
        CASE_STATUSES,
        start=1
    ):

        print(
            f"[{index}] {status}"
        )

    print()

    try:

        choice = int(
            input(
                "Select case status: "
            )
        )

    except ValueError:

        print()
        print(
            "[!] Enter a valid number."
        )

        return

    if (
        choice < 1
        or choice > len(CASE_STATUSES)
    ):

        print()
        print(
            "[!] Invalid status."
        )

        return

    new_status = CASE_STATUSES[
        choice - 1
    ]

    if update_case_status(
        case,
        new_status
    ):

        print()
        print(
            f"[✓] Case status changed to "
            f"{new_status}"
        )


def add_note_console(case):

    print()

    note = input(
        "Enter analyst note: "
    ).strip()

    if add_analyst_note(
        case,
        note
    ):

        print()
        print(
            "[✓] Analyst note added."
        )


def response_console(case):

    while True:

        print()

        print("=" * 70)
        print(
            f"TRACEX CASE: "
            f"{case.get('case_id')}"
        )
        print("=" * 70)

        print()

        print(
            "[1] View Case"
        )

        print(
            "[2] View Response Actions"
        )

        print(
            "[3] Add Response Action"
        )

        print(
            "[4] Update Action Status"
        )

        print(
            "[5] Update Case Status"
        )

        print(
            "[6] Add Analyst Note"
        )

        print(
            "[0] Back"
        )

        print()

        choice = input(
            "Select option: "
        ).strip()

        if choice == "1":

            display_case(case)

        elif choice == "2":

            show_response_actions(case)

        elif choice == "3":

            add_action_console(case)
            save_cases(
                CURRENT_CASES
            )

        elif choice == "4":

            update_action_console(case)
            save_cases(
                CURRENT_CASES
            )

        elif choice == "5":

            update_case_status_console(case)
            save_cases(
                CURRENT_CASES
            )

        elif choice == "6":

            add_note_console(case)
            save_cases(
                CURRENT_CASES
            )

        elif choice == "0":

            break

        else:

            print()
            print(
                "[!] Invalid option."
            )


def main():

    global CURRENT_CASES

    print()

    print("=" * 70)
    print("        TRACEX RESPONSE & INVESTIGATION ENGINE")
    print("=" * 70)

    CURRENT_CASES = load_cases()

    if not CURRENT_CASES:

        print()

        print(
            "[i] No investigation cases found."
        )

        print(
            "[i] Create a case before using "
            "the response workflow."
        )

        return

    case = select_case(
        CURRENT_CASES
    )

    if not case:

        return

    initialize_response_actions(
        case
    )

    initialize_notes(
        case
    )

    save_cases(
        CURRENT_CASES
    )

    response_console(
        case
    )

    save_cases(
        CURRENT_CASES
    )

    print()

    print(
        "[✓] Response workflow closed."
    )

    print(
        "[✓] Case data saved."
    )


if __name__ == "__main__":

    CURRENT_CASES = []

    main()
