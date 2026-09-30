import json
import os


CASES_FILE = "alerts/cases.json"


def load_cases():
    if not os.path.exists(CASES_FILE):
        return []

    try:
        with open(CASES_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def get_alert_ids(case):
    alert_ids = set()

    if case.get("alert_id"):
        alert_ids.add(case["alert_id"])

    for alert_id in case.get("related_alert_ids", []):
        alert_ids.add(alert_id)

    return alert_ids


def find_canonical_case(
    username=None,
    source_ip=None,
    alert_ids=None
):
    """
    Find the existing canonical investigation case.

    Priority:
    1. Active case with matching username + source IP
    2. Active case containing related alert IDs
    3. No matching case
    """

    cases = load_cases()

    alert_ids = set(alert_ids or [])

    candidates = []

    for case in cases:

        # Never select archived cases.
        if case.get("status") == "ARCHIVED":
            continue

        case_username = case.get("username")
        case_source_ip = case.get("source_ip")

        # -----------------------------------------
        # Match by username + source IP
        # -----------------------------------------

        if (
            username
            and source_ip
            and case_username == username
            and case_source_ip == source_ip
        ):
            candidates.append(case)
            continue

        # -----------------------------------------
        # Match by related alerts
        # -----------------------------------------

        case_alerts = get_alert_ids(case)

        if alert_ids.intersection(case_alerts):
            candidates.append(case)

    if not candidates:
        return None

    # Prefer INVESTIGATING cases.
    investigating = [
        case
        for case in candidates
        if case.get("status") == "INVESTIGATING"
    ]

    if investigating:
        return investigating[0]

    # Otherwise use highest-risk case.
    candidates.sort(
        key=lambda case: case.get("risk_score", 0),
        reverse=True
    )

    return candidates[0]


def display_case(case):

    if not case:
        print("\n[i] No existing canonical case found.")
        return

    print("\n========== CANONICAL CASE ==========")

    print(
        f"Case ID     : "
        f"{case.get('case_id')}"
    )

    print(
        f"Status      : "
        f"{case.get('status')}"
    )

    print(
        f"Username    : "
        f"{case.get('username')}"
    )

    print(
        f"Source IP   : "
        f"{case.get('source_ip')}"
    )

    print(
        f"Risk        : "
        f"{case.get('risk_score', 0)}/100 "
        f"{case.get('risk_level', 'UNKNOWN')}"
    )

    print(
        f"Alerts      : "
        f"{len(get_alert_ids(case))}"
    )

    print("====================================")


if __name__ == "__main__":

    print(
        "\n========== TRACEX CASE RESOLVER =========="
    )

    case = find_canonical_case(
        username="admin",
        source_ip="185.10.20.30",
        alert_ids=[
            "TRX-0001",
            "TRX-0009"
        ]
    )

    display_case(case)
