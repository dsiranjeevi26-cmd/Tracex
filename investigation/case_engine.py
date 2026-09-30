import json
from pathlib import Path
from datetime import datetime


BASE_DIR = Path(__file__).resolve().parent.parent

CORRELATION_FILE = (
    BASE_DIR
    / "alerts"
    / "correlation_results.json"
)

CASES_FILE = (
    BASE_DIR
    / "alerts"
    / "cases.json"
)


def load_json(file_path, default):

    try:

        with open(file_path, "r") as file:

            data = json.load(file)

            return data

    except (
        FileNotFoundError,
        json.JSONDecodeError
    ):

        return default


def save_json(file_path, data):

    file_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(file_path, "w") as file:

        json.dump(
            data,
            file,
            indent=4,
            default=str
        )


def load_correlations():

    data = load_json(
        CORRELATION_FILE,
        []
    )

    if isinstance(data, list):
        return data

    return []


def load_cases():

    data = load_json(
        CASES_FILE,
        []
    )

    if isinstance(data, list):
        return data

    return []


def generate_case_id(cases):

    numbers = []

    for case in cases:

        case_id = case.get(
            "case_id",
            ""
        )

        if not case_id.startswith("CASE-"):
            continue

        try:

            number = int(
                case_id.replace(
                    "CASE-",
                    ""
                )
            )

            numbers.append(number)

        except ValueError:

            continue

    next_number = (
        max(numbers, default=0) + 1
    )

    return f"CASE-{next_number:04d}"


def calculate_risk(correlation):

    counts = correlation.get(
        "event_counts",
        {}
    )

    failed = counts.get(
        "failed_logins",
        0
    )

    successful = counts.get(
        "successful_logins",
        0
    )

    sudo = counts.get(
        "sudo_events",
        0
    )

    account_changes = counts.get(
        "account_changes",
        0
    )

    score = 0

    factors = []

    if failed >= 5:

        score += 30

        factors.append(
            f"{failed} failed authentication "
            "attempts detected"
        )

    if successful >= 1:

        score += 20

        factors.append(
            "Successful login observed after "
            "failed authentication activity"
        )

    if sudo >= 1:

        score += 20

        factors.append(
            "Privileged command activity observed"
        )

    if account_changes >= 1:

        score += 20

        factors.append(
            "Account modification activity observed"
        )

    score = min(
        score,
        100
    )

    if score >= 80:

        level = "HIGH"

    elif score >= 50:

        level = "MEDIUM"

    else:

        level = "LOW"

    return {
        "score": score,
        "level": level,
        "factors": factors
    }


def case_already_exists(
    cases,
    alert_ids
):

    alert_ids = set(
        alert_ids
    )

    for case in cases:

        existing_ids = set(
            case.get(
                "related_alert_ids",
                []
            )
        )

        if alert_ids.intersection(
            existing_ids
        ):

            return True

    return False


def build_case(
    correlation,
    cases
):

    risk = calculate_risk(
        correlation
    )

    now = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    case = {

        "case_id": generate_case_id(
            cases
        ),

        "status": "NEW",

        "created_at": now,

        "updated_at": now,

        "username":
            correlation.get(
                "username"
            ),

        "source_ip":
            correlation.get(
                "source_ip"
            ),

        "service":
            correlation.get(
                "service"
            ),

        "related_alert_ids":
            correlation.get(
                "related_alert_ids",
                []
            ),

        "detection_rules":
            correlation.get(
                "detection_rules",
                []
            ),

        "event_counts":
            correlation.get(
                "event_counts",
                {}
            ),

        "timeline":
            correlation.get(
                "timeline",
                []
            ),

        "correlation_reason":
            correlation.get(
                "correlation_reason",
                ""
            ),

        "risk_score":
            risk["score"],

        "risk_level":
            risk["level"],

        "risk_factors":
            risk["factors"],

        "analyst_notes": [],

        "mitre_mappings": [],

        "response_actions": []
    }

    return case


def display_case(case):

    print()
    print("=" * 60)
    print("             TRACEX INVESTIGATION CASE")
    print("=" * 60)

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

    print("---------- RELATED ALERTS ----------")

    for alert_id in case.get(
        "related_alert_ids",
        []
    ):

        print(
            f"  • {alert_id}"
        )

    print()

    print("---------- DETECTION RULES ----------")

    for rule in case.get(
        "detection_rules",
        []
    ):

        print(
            f"  • {rule}"
        )

    print()

    print("---------- CORRELATED EVIDENCE ----------")

    counts = case.get(
        "event_counts",
        {}
    )

    print(
        f"Failed Logins      : "
        f"{counts.get('failed_logins', 0)}"
    )

    print(
        f"Successful Logins  : "
        f"{counts.get('successful_logins', 0)}"
    )

    print(
        f"Sudo Events        : "
        f"{counts.get('sudo_events', 0)}"
    )

    print(
        f"Account Changes    : "
        f"{counts.get('account_changes', 0)}"
    )

    print()

    print("---------- RISK ASSESSMENT ----------")

    print(
        f"Risk Score         : "
        f"{case.get('risk_score')}/100"
    )

    print(
        f"Risk Level         : "
        f"{case.get('risk_level')}"
    )

    print()

    print("Risk Factors:")

    for factor in case.get(
        "risk_factors",
        []
    ):

        print(
            f"  • {factor}"
        )

    print()

    print("---------- ANALYST ASSESSMENT ----------")

    print(
        "The case contains correlated security "
        "evidence requiring investigation."
    )

    print(
        "The risk score prioritizes investigation "
        "and does not independently confirm "
        "malicious activity."
    )

    print()

    print("=" * 60)


def main():

    print()
    print("=" * 60)
    print("          TRACEX CASE ENGINE")
    print("=" * 60)

    correlations = load_correlations()

    if not correlations:

        print()
        print(
            "[i] No correlation results found."
        )

        print(
            "[i] Run the correlation engine first."
        )

        return

    cases = load_cases()

    created_cases = 0

    for correlation in correlations:

        alert_ids = correlation.get(
            "related_alert_ids",
            []
        )

        if not alert_ids:

            print(
                "[i] Correlation has no "
                "associated alerts."
            )

            continue

        if case_already_exists(
            cases,
            alert_ids
        ):

            print()

            print(
                "[i] Case already exists "
                "for related alert activity."
            )

            continue

        case = build_case(
            correlation,
            cases
        )

        cases.append(case)

        save_json(
            CASES_FILE,
            cases
        )

        display_case(case)

        created_cases += 1

    print()

    print("=" * 60)

    print(
        f"[+] New cases created : "
        f"{created_cases}"
    )

    print(
        f"[+] Total cases       : "
        f"{len(cases)}"
    )

    print(
        f"[✓] Cases saved to     : "
        f"{CASES_FILE}"
    )

    print("=" * 60)


if __name__ == "__main__":

    main()
