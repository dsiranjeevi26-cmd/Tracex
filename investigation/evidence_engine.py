import json
import os
from datetime import datetime


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CASES_FILE = os.path.join(BASE_DIR, "alerts", "cases.json")
CORRELATION_FILE = os.path.join(
    BASE_DIR,
    "alerts",
    "correlation_results.json"
)


def load_json(path, default):
    try:
        with open(path, "r") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_json(path, data):
    with open(path, "w") as file:
        json.dump(data, file, indent=4)


def normalize_cases(data):
    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        if isinstance(data.get("cases"), list):
            return data["cases"]

        return [data]

    return []


def normalize_correlations(data):
    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        if isinstance(data.get("correlations"), list):
            return data["correlations"]

        return [data]

    return []


def find_correlation(case, correlations):
    username = case.get("username")
    source_ip = case.get("source_ip")

    for correlation in correlations:
        if (
            correlation.get("username") == username
            and correlation.get("source_ip") == source_ip
        ):
            return correlation

    return None


def show_evidence(case, correlation):
    print("\n" + "=" * 60)
    print("          TRACEX EVIDENCE CHAIN")
    print("=" * 60)

    print(f"Case ID       : {case.get('case_id', 'N/A')}")
    print(f"Username      : {case.get('username', 'N/A')}")
    print(f"Source IP     : {case.get('source_ip', 'N/A')}")
    print(f"Risk Score    : {case.get('risk_score', 0)}/100")
    print(f"Risk Level    : {case.get('risk_level', 'UNKNOWN')}")

    print("\n--- EVIDENCE SUMMARY ---")

    event_counts = correlation.get("event_counts", {})

    failed = event_counts.get("failed_logins", 0)
    successful = event_counts.get("successful_logins", 0)
    sudo = event_counts.get("sudo_events", 0)
    account_changes = event_counts.get("account_changes", 0)

    print(f"Failed Logins       : {failed}")
    print(f"Successful Logins   : {successful}")
    print(f"Sudo Events         : {sudo}")
    print(f"Account Changes     : {account_changes}")

    print("\n--- DETECTION RULES ---")

    rules = correlation.get("detection_rules", [])

    if rules:
        for rule in rules:
            print(f"• {rule}")
    else:
        print("None")

    timeline = correlation.get("timeline", [])

    print("\n--- TIMELINE ---")
    print(f"Timeline Events     : {len(timeline)}")

    if timeline:
        for event in timeline:
            print(
                f"• {event.get('timestamp', 'N/A')} | "
                f"{event.get('event', 'Unknown event')}"
            )

    print("\n--- ANALYST GUIDANCE ---")

    if failed >= 5 and successful >= 1:
        print(
            "Authentication failures were followed by a successful login."
        )

    if sudo > 0:
        print(
            "Privileged activity was observed and requires validation."
        )

    if account_changes > 0:
        print(
            "Account modification activity was observed."
        )

    print(
        "\nTraceX does not automatically classify the activity as malicious."
    )

    print(
        "Analyst validation is required before final case resolution."
    )


def save_decision(case, decision):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    case["analyst_decision"] = decision
    case["decision_timestamp"] = timestamp

    # Maintain a decision history
    if "decision_history" not in case:
        case["decision_history"] = []

    case["decision_history"].append(
        {
            "decision": decision,
            "timestamp": timestamp
        }
    )


def analyst_decision(case, cases):
    print("\n" + "=" * 60)
    print("          ANALYST DECISION")
    print("=" * 60)

    print("\n1. CONTINUE_INVESTIGATION")
    print("2. ESCALATE")
    print("3. RESOLVE")
    print("0. CANCEL")

    choice = input("\nSelect decision: ").strip()

    decisions = {
        "1": "CONTINUE_INVESTIGATION",
        "2": "ESCALATE",
        "3": "RESOLVE"
    }

    if choice == "0":
        print("\n[!] Decision cancelled.")
        return

    decision = decisions.get(choice)

    if not decision:
        print("\n[!] Invalid choice.")
        return

    save_decision(case, decision)

    save_json(CASES_FILE, cases)

    print("\n" + "-" * 60)
    print("ANALYST DECISION SAVED")
    print("-" * 60)

    print(f"Case ID          : {case.get('case_id')}")
    print(f"Decision         : {decision}")
    print(f"Timestamp        : {case.get('decision_timestamp')}")

    if decision == "CONTINUE_INVESTIGATION":
        print(
            "Guidance         : Continue collecting and validating evidence."
        )

    elif decision == "ESCALATE":
        print(
            "Guidance         : Escalate the case for higher-level review."
        )

    elif decision == "RESOLVE":
        print(
            "Guidance         : Analyst has selected case resolution."
        )

    print("\n[+] Decision persisted to cases.json")


def select_case(cases):
    if not cases:
        print("\n[!] No cases available.")
        return None

    print("\n" + "=" * 60)
    print("             AVAILABLE CASES")
    print("=" * 60)

    for index, case in enumerate(cases, start=1):
        print(
            f"{index}. "
            f"{case.get('case_id', 'N/A')} | "
            f"{case.get('username', 'N/A')} | "
            f"{case.get('source_ip', 'N/A')} | "
            f"Risk: {case.get('risk_score', 0)}/100 "
            f"{case.get('risk_level', 'UNKNOWN')}"
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


def main():
    print("\n" + "=" * 60)
    print("       TRACEX EVIDENCE + ANALYST DECISION ENGINE")
    print("=" * 60)

    raw_cases = load_json(CASES_FILE, [])
    raw_correlations = load_json(CORRELATION_FILE, [])

    cases = normalize_cases(raw_cases)
    correlations = normalize_correlations(raw_correlations)

    print(f"\nCases loaded        : {len(cases)}")
    print(f"Correlation groups  : {len(correlations)}")

    case = select_case(cases)

    if not case:
        return

    correlation = find_correlation(case, correlations)

    if not correlation:
        print("\n[!] No matching correlation evidence found.")
        return

    show_evidence(case, correlation)

    analyst_decision(case, cases)


if __name__ == "__main__":
    main()
