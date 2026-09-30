import json
from datetime import datetime
from pathlib import Path


CASES_FILE = "alerts/cases.json"
CORRELATION_FILE = "alerts/correlation_results.json"
REPORT_DIR = Path("reports/generated")


def load_json(file_path, default):
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_json(file_path, data):
    with open(file_path, "w") as f:
        json.dump(data, f, indent=4)


def select_case(cases):
    if not cases:
        print("\n[!] No cases available.")
        return None

    print("\n========== AVAILABLE CASES ==========")

    for case in cases:
        print(
            f"{case.get('case_id', 'N/A')} | "
            f"{case.get('username', 'N/A')} | "
            f"{case.get('source_ip', 'N/A')} | "
            f"Risk: {case.get('risk_score', 'N/A')}/100 | "
            f"Status: {case.get('status', 'N/A')}"
        )

    case_id = input("\nEnter Case ID: ").strip()

    for case in cases:
        if case.get("case_id") == case_id:
            return case

    print("[!] Case not found.")
    return None


def build_response_summary(case):
    response_actions = case.get("response_actions", [])

    status_counts = {
        "RECOMMENDED": 0,
        "IN_PROGRESS": 0,
        "COMPLETED": 0,
        "SKIPPED": 0
    }

    for action in response_actions:
        status = action.get("status", "RECOMMENDED")

        if status in status_counts:
            status_counts[status] += 1

    return {
        "total_actions": len(response_actions),
        "status_counts": status_counts,
        "completed_actions": [
            action
            for action in response_actions
            if action.get("status") == "COMPLETED"
        ],
        "in_progress_actions": [
            action
            for action in response_actions
            if action.get("status") == "IN_PROGRESS"
        ],
        "recommended_actions": [
            action
            for action in response_actions
            if action.get("status") == "RECOMMENDED"
        ],
        "skipped_actions": [
            action
            for action in response_actions
            if action.get("status") == "SKIPPED"
        ]
    }


def generate_report(case, correlation_data):
    case_id = case.get("case_id", "N/A")

    username = case.get("username", "N/A")
    source_ip = case.get("source_ip", "N/A")

    risk_score = case.get("risk_score", 0)
    risk_level = case.get("risk_level", "UNKNOWN")

    detection_rules = case.get("detection_rules", [])

    evidence_counts = {
        "failed_logins": case.get("failed_logins", 0),
        "successful_logins": case.get("successful_logins", 0),
        "sudo_events": case.get("sudo_events", 0),
        "account_changes": case.get("account_changes", 0)
    }

    mitre_mappings = case.get("mitre_mappings", [])
    mitre_evidence = case.get("mitre_evidence", [])

    timeline = case.get("timeline", [])

    analyst_briefing = case.get("analyst_briefing", {})

    analyst_notes = case.get("analyst_notes", [])
    investigation_activity = case.get(
        "investigation_activity",
        []
    )

    decision_history = case.get(
        "decision_history",
        []
    )

    status_history = case.get(
        "status_history",
        []
    )

    reopen_history = case.get(
        "reopen_history",
        []
    )

    resolution = case.get(
        "resolution",
        {}
    )

    response_actions = case.get(
        "response_actions",
        []
    )

    response_activity_history = case.get(
        "response_activity_history",
        []
    )

    response_summary = build_response_summary(case)

    report = {
        "report_id": f"INV-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "generated_at": datetime.now().isoformat(),

        "case_information": {
            "case_id": case_id,
            "username": username,
            "source_ip": source_ip,
            "status": case.get("status", "N/A"),
            "created_at": case.get("created_at"),
            "updated_at": case.get("updated_at")
        },

        "risk_assessment": {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_factors": case.get("risk_factors", [])
        },

        "detection_summary": {
            "detection_rules": detection_rules,
            "related_alert_ids": case.get(
                "related_alert_ids",
                []
            )
        },

        "evidence_summary": evidence_counts,

        "correlation": {
            "matched_group": {
                "username": username,
                "source_ip": source_ip
            },
            "correlation_data_available": bool(correlation_data)
        },

        "timeline": timeline,

        "mitre_attack": {
            "mappings": mitre_mappings,
            "evidence": mitre_evidence
        },

        "analyst_briefing": analyst_briefing,

        "analyst_decisions": {
            "current_decision": case.get(
                "analyst_decision"
            ),
            "decision_history": decision_history
        },

        "investigation": {
            "analyst_notes": analyst_notes,
            "investigation_activity": investigation_activity
        },

        "response": {
            "actions": response_actions,
            "activity_history": response_activity_history,
            "summary": response_summary
        },

        "case_lifecycle": {
            "status_history": status_history,
            "reopen_history": reopen_history,
            "resolution": resolution
        },

        "analyst_assessment": (
            "TraceX identified correlated security-relevant "
            "events associated with this case. The evidence "
            "is presented for analyst investigation and "
            "decision-making. Detection and MITRE mappings "
            "do not independently confirm malicious activity."
        )
    }

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    report_path = (
        REPORT_DIR /
        f"{report['report_id']}.json"
    )

    save_json(
        report_path,
        report
    )

    return report, report_path


def display_report(report):
    case_info = report["case_information"]
    risk = report["risk_assessment"]
    detection = report["detection_summary"]
    evidence = report["evidence_summary"]
    mitre = report["mitre_attack"]
    response = report["response"]

    print("\n")
    print("=" * 65)
    print("             TRACEX INVESTIGATION REPORT")
    print("=" * 65)

    print("\n[CASE INFORMATION]")
    print(f"Report ID   : {report['report_id']}")
    print(f"Case ID     : {case_info['case_id']}")
    print(f"Username    : {case_info['username']}")
    print(f"Source IP   : {case_info['source_ip']}")
    print(f"Status      : {case_info['status']}")

    print("\n[RISK ASSESSMENT]")
    print(f"Risk Score  : {risk['risk_score']}/100")
    print(f"Risk Level  : {risk['risk_level']}")

    print("\n[DETECTION SUMMARY]")

    if detection["detection_rules"]:
        for rule in detection["detection_rules"]:
            print(f"- {rule}")
    else:
        print("- No detection rules recorded")

    print("\n[EVIDENCE SUMMARY]")
    print(
        f"Failed Logins       : "
        f"{evidence['failed_logins']}"
    )

    print(
        f"Successful Logins   : "
        f"{evidence['successful_logins']}"
    )

    print(
        f"Sudo Events         : "
        f"{evidence['sudo_events']}"
    )

    print(
        f"Account Changes     : "
        f"{evidence['account_changes']}"
    )

    print("\n[MITRE ATT&CK CONTEXT]")

    if mitre["mappings"]:
        for mapping in mitre["mappings"]:
            if isinstance(mapping, dict):
                print(
                    f"- {mapping.get('technique_id', 'N/A')} : "
                    f"{mapping.get('technique_name', 'N/A')}"
                )
            else:
                print(f"- {mapping}")
    else:
        print("- No MITRE mappings recorded")

    print("\n[ANALYST DECISION]")
    print(
        f"Current Decision : "
        f"{report['analyst_decisions']['current_decision']}"
    )

    print("\n[RESPONSE ACTIVITY]")

    print(
        f"Total Actions : "
        f"{response['summary']['total_actions']}"
    )

    print(
        f"Recommended   : "
        f"{response['summary']['status_counts']['RECOMMENDED']}"
    )

    print(
        f"In Progress   : "
        f"{response['summary']['status_counts']['IN_PROGRESS']}"
    )

    print(
        f"Completed     : "
        f"{response['summary']['status_counts']['COMPLETED']}"
    )

    print(
        f"Skipped       : "
        f"{response['summary']['status_counts']['SKIPPED']}"
    )

    if response["actions"]:
        print("\nResponse Actions:")

        for index, action in enumerate(
            response["actions"],
            start=1
        ):
            print(
                f"{index}. "
                f"{action.get('action', 'N/A')} | "
                f"{action.get('status', 'N/A')}"
            )

            if action.get("note"):
                print(
                    f"   Note: "
                    f"{action.get('note')}"
                )

    print("\n[INVESTIGATION ACTIVITY]")
    print(
        f"Notes      : "
        f"{len(report['investigation']['analyst_notes'])}"
    )

    print(
        f"Activities : "
        f"{len(report['investigation']['investigation_activity'])}"
    )

    print(
        f"Decisions  : "
        f"{len(report['analyst_decisions']['decision_history'])}"
    )

    print(
        f"Status Changes : "
        f"{len(report['case_lifecycle']['status_history'])}"
    )

    print("\n[ANALYST ASSESSMENT]")
    print(
        report["analyst_assessment"]
    )

    print("\n" + "=" * 65)
    print("Investigation report generated successfully.")
    print("=" * 65)


def main():
    print("\n========== TRACEX INVESTIGATION REPORT ==========")

    cases = load_json(
        CASES_FILE,
        []
    )

    correlation_data = load_json(
        CORRELATION_FILE,
        []
    )

    if isinstance(cases, dict):
        cases = list(cases.values())

    case = select_case(cases)

    if not case:
        return

    report, report_path = generate_report(
        case,
        correlation_data
    )

    display_report(report)

    print(
        f"\n[+] Saved to: {report_path}"
    )


if __name__ == "__main__":
    main()
