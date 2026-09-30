import json
from datetime import datetime
from pathlib import Path

from correlation.correlator import correlate_events
from risk.risk_engine import calculate_risk, get_risk_level


# --------------------------------------------------
# TraceX Case Manager
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

CASE_FILE = BASE_DIR / "alerts" / "cases.json"
ALERT_FILE = BASE_DIR / "alerts" / "alerts.json"


ALLOWED_STATUSES = [
    "NEW",
    "ACKNOWLEDGED",
    "INVESTIGATING",
    "RESOLVED"
]


def load_cases():

    try:

        with open(CASE_FILE, "r") as file:
            data = json.load(file)

            if isinstance(data, list):
                return data

            return []

    except (FileNotFoundError, json.JSONDecodeError):

        return []


def save_cases(cases):

    with open(CASE_FILE, "w") as file:

        json.dump(
            cases,
            file,
            indent=4
        )


def load_alerts():

    try:

        with open(ALERT_FILE, "r") as file:
            data = json.load(file)

            if isinstance(data, list):
                return data

            return []

    except (FileNotFoundError, json.JSONDecodeError):

        return []


def generate_case_id(cases):

    numbers = []

    for case in cases:

        case_id = case.get("case_id", "")

        if not case_id.startswith("CASE-"):
            continue

        try:

            number = int(
                case_id.replace("CASE-", "")
            )

            numbers.append(number)

        except ValueError:

            continue

    next_number = max(numbers, default=0) + 1

    return f"CASE-{next_number:04d}"


def find_case(cases, case_id):

    for case in cases:

        if case.get("case_id") == case_id:
            return case

    return None


def find_case_by_alert(cases, alert_id):

    for case in cases:

        if case.get("alert_id") == alert_id:
            return case

    return None


def find_alert(alert_id):

    alerts = load_alerts()

    for alert in alerts:

        if alert.get("alert_id") == alert_id:
            return alert

    return None


def find_correlated_case(alert):

    cases = correlate_events()

    for case in cases:

        if (
            case.get("username") == alert.get("username")
            and
            case.get("source_ip") == alert.get("source_ip")
        ):

            return case

    return None


def calculate_case_risk(alert):

    correlated_case = find_correlated_case(alert)

    if correlated_case is None:

        return None, None

    score, reasons = calculate_risk(
        correlated_case
    )

    risk_level = get_risk_level(score)

    return score, risk_level


def create_case():

    alert_id = input(
        "\nEnter Alert ID: "
    ).strip()

    if not alert_id:

        print("\nAlert ID cannot be empty.")
        return

    # Make sure the alert actually exists.

    alert = find_alert(alert_id)

    if alert is None:

        print(
            f"\nAlert {alert_id} was not found."
        )

        return

    cases = load_cases()

    # Prevent duplicate cases.

    existing_case = find_case_by_alert(
        cases,
        alert_id
    )

    if existing_case:

        print(
            f"\nCase already exists: "
            f"{existing_case['case_id']}"
        )

        return

    # Automatically calculate risk.

    risk_score, risk_level = calculate_case_risk(
        alert
    )

    now = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    case = {

        "case_id": generate_case_id(cases),

        "alert_id": alert_id,

        "status": "NEW",

        "created_at": now,

        "updated_at": now,

        "risk_score": risk_score,

        "risk_level": risk_level,

        "analyst_notes": []

    }

    cases.append(case)

    save_cases(cases)

    print(
        "\n========== CASE CREATED ==========\n"
    )

    print(
        f"Case ID    : {case['case_id']}"
    )

    print(
        f"Alert ID   : {case['alert_id']}"
    )

    print(
        f"Status     : {case['status']}"
    )

    print(
        f"Risk Score : "
        f"{case['risk_score']}/100"
        if case["risk_score"] is not None
        else "Risk Score : N/A"
    )

    print(
        f"Risk Level : "
        f"{case['risk_level']}"
        if case["risk_level"] is not None
        else "Risk Level : N/A"
    )

    print()


def show_cases():

    cases = load_cases()

    if not cases:

        print("\nNo cases found.\n")
        return

    print(
        "\n========== TRACEX CASES ==========\n"
    )

    for case in cases:

        risk_score = case.get(
            "risk_score"
        )

        if risk_score is None:
            risk_display = "N/A"
        else:
            risk_display = f"{risk_score}/100"

        print(
            f"Case ID       : "
            f"{case.get('case_id', 'N/A')}"
        )

        print(
            f"Alert ID      : "
            f"{case.get('alert_id', 'N/A')}"
        )

        print(
            f"Status        : "
            f"{case.get('status', 'N/A')}"
        )

        print(
            f"Risk Score    : "
            f"{risk_display}"
        )

        print(
            f"Risk Level    : "
            f"{case.get('risk_level', 'N/A')}"
        )

        print(
            f"Created       : "
            f"{case.get('created_at', 'N/A')}"
        )

        print(
            f"Updated       : "
            f"{case.get('updated_at', 'N/A')}"
        )

        print(
            f"Notes         : "
            f"{len(case.get('analyst_notes', []))}"
        )

        print(
            "-----------------------------------"
        )

    print()


def update_status():

    case_id = input(
        "\nEnter Case ID: "
    ).strip()

    cases = load_cases()

    case = find_case(
        cases,
        case_id
    )

    if case is None:

        print(
            f"\nCase {case_id} not found."
        )

        return

    print("\nAllowed statuses:")

    for status in ALLOWED_STATUSES:

        print(f"  {status}")

    new_status = input(
        "\nEnter new status: "
    ).strip().upper()

    if new_status not in ALLOWED_STATUSES:

        print("\nInvalid status.")
        return

    case["status"] = new_status

    case["updated_at"] = (
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )

    save_cases(cases)

    print(
        f"\n{case_id} status updated to "
        f"{new_status}."
    )


def add_note():

    case_id = input(
        "\nEnter Case ID: "
    ).strip()

    cases = load_cases()

    case = find_case(
        cases,
        case_id
    )

    if case is None:

        print(
            f"\nCase {case_id} not found."
        )

        return

    note = input(
        "\nEnter analyst note: "
    ).strip()

    if not note:

        print("\nNote cannot be empty.")
        return

    analyst_note = {

        "timestamp":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

        "note": note

    }

    if "analyst_notes" not in case:

        case["analyst_notes"] = []

    case["analyst_notes"].append(
        analyst_note
    )

    case["updated_at"] = (
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )

    save_cases(cases)

    print(
        "\nAnalyst note added successfully."
    )


def show_case_details():

    case_id = input(
        "\nEnter Case ID: "
    ).strip()

    cases = load_cases()

    case = find_case(
        cases,
        case_id
    )

    if case is None:

        print(
            f"\nCase {case_id} not found."
        )

        return

    risk_score = case.get(
        "risk_score"
    )

    if risk_score is None:
        risk_display = "N/A"
    else:
        risk_display = f"{risk_score}/100"

    print(
        "\n========== CASE DETAILS ==========\n"
    )

    print(
        f"Case ID       : {case['case_id']}"
    )

    print(
        f"Alert ID      : {case['alert_id']}"
    )

    print(
        f"Status        : {case['status']}"
    )

    print(
        f"Risk Score    : {risk_display}"
    )

    print(
        f"Risk Level    : "
        f"{case.get('risk_level', 'N/A')}"
    )

    print(
        f"Created       : {case['created_at']}"
    )

    print(
        f"Updated       : {case['updated_at']}"
    )

    print("\nAnalyst Notes:")

    notes = case.get(
        "analyst_notes",
        []
    )

    if not notes:

        print("  No analyst notes.")

    else:

        for note in notes:

            print(
                f"\n  [{note['timestamp']}]"
            )

            print(
                f"  {note['note']}"
            )

    print(
        "\n===================================\n"
    )


def main():

    while True:

        print(
            "\n========== TRACEX CASE MANAGER =========="
        )

        print("1. Create Case")
        print("2. View Cases")
        print("3. View Case Details")
        print("4. Update Case Status")
        print("5. Add Analyst Note")
        print("6. Exit")

        choice = input(
            "\nSelect an option: "
        ).strip()

        if choice == "1":

            create_case()

        elif choice == "2":

            show_cases()

        elif choice == "3":

            show_case_details()

        elif choice == "4":

            update_status()

        elif choice == "5":

            add_note()

        elif choice == "6":

            print(
                "\nExiting TraceX Case Manager."
            )

            break

        else:

            print(
                "\nInvalid option."
            )


if __name__ == "__main__":

    main()
