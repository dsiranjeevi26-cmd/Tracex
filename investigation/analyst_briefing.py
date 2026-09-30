import json
import os
from datetime import datetime


CASES_FILE = "alerts/cases.json"
CORRELATION_FILE = "alerts/correlation_results.json"


def load_json(path, default):
    if not os.path.exists(path):
        return default

    try:
        with open(path, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        print(f"[!] Invalid JSON: {path}")
        return default


def save_cases(cases):
    with open(CASES_FILE, "w") as f:
        json.dump(cases, f, indent=4)


def find_correlation(case, correlations):
    username = case.get("username")
    source_ip = case.get("source_ip")

    for correlation in correlations:
        if (
            correlation.get("username") == username
            and correlation.get("source_ip") == source_ip
        ):
            return correlation

    return {}


def select_case(cases):
    print("\n========== TRACEX SOC BRIEFING ==========\n")

    for case in cases:
        print(
            f"{case.get('case_id')} | "
            f"{case.get('username')} | "
            f"{case.get('source_ip')} | "
            f"Status: {case.get('status')} | "
            f"Risk: {case.get('risk_score', 0)}/100 "
            f"{case.get('risk_level', 'UNKNOWN')}"
        )

    case_id = input("\nEnter Case ID: ").strip()

    for case in cases:
        if case.get("case_id") == case_id:
            return case

    print("[!] Case not found.")
    return None


def build_briefing(case, correlation):
    counts = correlation.get(
        "event_counts",
        case.get("event_counts", {})
    )

    failed = counts.get("failed_logins", 0)
    successful = counts.get("successful_logins", 0)
    sudo = counts.get("sudo_events", 0)
    account_changes = counts.get("account_changes", 0)

    rules = correlation.get(
        "detection_rules",
        case.get("detection_rules", [])
    )

    mitre = case.get(
        "mitre_evidence",
        case.get("mitre_mappings", [])
    )

    risk_score = case.get("risk_score", 0)
    risk_level = case.get("risk_level", "UNKNOWN")

    evidence_parts = []

    if failed:
        evidence_parts.append(
            f"{failed} failed authentication attempts"
        )

    if successful:
        evidence_parts.append(
            f"{successful} successful authentication event(s)"
        )

    if sudo:
        evidence_parts.append(
            f"{sudo} privileged sudo event(s)"
        )

    if account_changes:
        evidence_parts.append(
            f"{account_changes} account modification event(s)"
        )

    if evidence_parts:
        evidence_summary = "; ".join(evidence_parts) + "."
    else:
        evidence_summary = (
            "No significant correlated activity was found."
        )

    if risk_score >= 80:
        assessment = (
            "Multiple correlated security indicators are present. "
            "Detailed analyst validation is required."
        )
    elif risk_score >= 50:
        assessment = (
            "Relevant security indicators are present. "
            "Additional investigation is recommended."
        )
    elif risk_score > 0:
        assessment = (
            "Limited security evidence is present. "
            "Further validation is recommended before escalation."
        )
    else:
        assessment = (
            "Insufficient evidence is currently available "
            "for a strong investigation assessment."
        )

    mitre_summary = []

    for item in mitre:
        technique_id = item.get("technique_id")
        technique_name = item.get("technique_name")

        if technique_id and technique_name:
            mitre_summary.append(
                f"{technique_id} - {technique_name}"
            )

    decision = case.get(
        "analyst_decision",
        "NOT_RECORDED"
    )

    return {
        "generated_at": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "case_id": case.get("case_id"),
        "subject": {
            "username": case.get("username"),
            "source_ip": case.get("source_ip")
        },
        "case_status": case.get("status"),
        "risk": {
            "score": risk_score,
            "level": risk_level
        },
        "detection_rules": rules,
        "evidence_summary": evidence_summary,
        "event_counts": {
            "failed_logins": failed,
            "successful_logins": successful,
            "sudo_events": sudo,
            "account_changes": account_changes
        },
        "mitre_techniques": mitre_summary,
        "analyst_assessment": assessment,
        "analyst_decision": decision
    }


def display_briefing(briefing):
    print("\n")
    print("=" * 60)
    print("             TRACEX SOC ANALYST BRIEFING")
    print("=" * 60)

    print(f"\nCase ID       : {briefing['case_id']}")
    print(
        f"Subject       : "
        f"{briefing['subject']['username']}"
    )
    print(
        f"Source IP     : "
        f"{briefing['subject']['source_ip']}"
    )
    print(
        f"Case Status   : "
        f"{briefing['case_status']}"
    )
    print(
        f"Risk          : "
        f"{briefing['risk']['score']}/100 "
        f"{briefing['risk']['level']}"
    )

    print("\n---------------- DETECTION RULES ----------------")

    for rule in briefing["detection_rules"]:
        print(f"• {rule}")

    if not briefing["detection_rules"]:
        print("• None")

    print("\n---------------- EVENT EVIDENCE ----------------")

    counts = briefing["event_counts"]

    print(f"Failed Logins       : {counts['failed_logins']}")
    print(f"Successful Logins   : {counts['successful_logins']}")
    print(f"Sudo Events         : {counts['sudo_events']}")
    print(f"Account Changes     : {counts['account_changes']}")

    print("\nEvidence Summary:")
    print(f"• {briefing['evidence_summary']}")

    print("\n---------------- MITRE ATT&CK ----------------")

    if briefing["mitre_techniques"]:
        for technique in briefing["mitre_techniques"]:
            print(f"• {technique}")
    else:
        print("• No MITRE mapping recorded.")

    print("\n---------------- ANALYST ASSESSMENT ----------------")
    print(f"• {briefing['analyst_assessment']}")

    print("\n---------------- DECISION ----------------")
    print(f"• {briefing['analyst_decision']}")

    print("\n============================================================")
    print("                    END OF BRIEFING")
    print("============================================================")


def main():
    cases = load_json(CASES_FILE, [])
    correlations = load_json(CORRELATION_FILE, [])

    if not cases:
        print("[!] No cases available.")
        return

    case = select_case(cases)

    if not case:
        return

    correlation = find_correlation(
        case,
        correlations
    )

    briefing = build_briefing(
        case,
        correlation
    )

    # Persist briefing inside the case
    case["analyst_briefing"] = briefing
    case["updated_at"] = datetime.now().isoformat()

    save_cases(cases)

    display_briefing(briefing)

    print("\n[+] Analyst briefing saved to cases.json")


if __name__ == "__main__":
    main()
