import json
import os
from datetime import datetime


# ============================================================
# TRACEX INCIDENT REPORT GENERATOR
# ============================================================

CASES_FILE = "alerts/cases.json"
ALERTS_FILE = "alerts/alerts.json"
CORRELATION_FILE = "alerts/correlation_results.json"

REPORTS_DIR = "reports/generated"


# ============================================================
# JSON HELPERS
# ============================================================

def load_json(file_path, default):
    if not os.path.exists(file_path):
        return default

    try:
        with open(file_path, "r") as f:
            return json.load(f)

    except (json.JSONDecodeError, OSError):
        return default


def save_json(file_path, data):
    try:
        with open(file_path, "w") as f:
            json.dump(data, f, indent=4, default=str)

        return True

    except OSError:
        return False


# ============================================================
# NORMALIZATION
# ============================================================

def as_list(data):
    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        return [data]

    return []


def safe(value, default="N/A"):
    if value is None or value == "":
        return default

    return value


def get_case_id(case):
    return case.get("case_id", "UNKNOWN")


# ============================================================
# FIND RELATED DATA
# ============================================================

def find_alerts_for_case(case, alerts):

    related_ids = case.get("related_alert_ids", [])

    if not isinstance(related_ids, list):
        related_ids = []

    alert_id = case.get("alert_id")

    if alert_id and alert_id not in related_ids:
        related_ids.append(alert_id)

    matched = []

    for alert in alerts:

        current_id = alert.get("alert_id")

        if current_id in related_ids:
            matched.append(alert)

    return matched


def find_correlation(case, correlations):

    case_username = case.get("username")
    case_ip = case.get("source_ip")

    for correlation in correlations:

        if (
            correlation.get("username") == case_username
            and
            correlation.get("source_ip") == case_ip
        ):
            return correlation

    return {}


# ============================================================
# EVIDENCE SUMMARY
# ============================================================

def build_evidence_summary(case, correlation):

    failed = correlation.get(
        "failed_logins",
        case.get("failed_logins", 0)
    )

    successful = correlation.get(
        "successful_logins",
        case.get("successful_logins", 0)
    )

    sudo = correlation.get(
        "sudo_events",
        case.get("sudo_events", 0)
    )

    account_changes = correlation.get(
        "account_changes",
        case.get("account_changes", 0)
    )

    evidence = []

    if failed:
        evidence.append({
            "type": "FAILED_AUTHENTICATION",
            "count": failed,
            "description":
                f"{failed} failed authentication attempt(s) observed."
        })

    if successful:
        evidence.append({
            "type": "SUCCESSFUL_AUTHENTICATION",
            "count": successful,
            "description":
                f"{successful} successful authentication event(s) observed."
        })

    if sudo:
        evidence.append({
            "type": "PRIVILEGED_ACTIVITY",
            "count": sudo,
            "description":
                f"{sudo} privileged activity event(s) observed."
        })

    if account_changes:
        evidence.append({
            "type": "ACCOUNT_MODIFICATION",
            "count": account_changes,
            "description":
                f"{account_changes} account modification event(s) observed."
        })

    return {
        "failed_logins": failed,
        "successful_logins": successful,
        "sudo_events": sudo,
        "account_changes": account_changes,
        "supporting_indicators": len(evidence),
        "evidence": evidence
    }


# ============================================================
# DETECTION SUMMARY
# ============================================================

def build_detection_summary(case, alerts):

    rules = case.get("detection_rules", [])

    if not isinstance(rules, list):
        rules = []

    related_alerts = find_alerts_for_case(case, alerts)

    alert_summary = []

    for alert in related_alerts:

        alert_summary.append({
            "alert_id": alert.get("alert_id"),
            "rule": alert.get(
                "detection_rule",
                alert.get("rule", "N/A")
            ),
            "severity": alert.get("severity", "N/A"),
            "timestamp": alert.get("timestamp", "N/A"),
            "service": alert.get("service", "N/A")
        })

    return {
        "detection_rules": rules,
        "related_alert_count": len(related_alerts),
        "related_alerts": alert_summary
    }


# ============================================================
# MITRE SUMMARY
# ============================================================

def build_mitre_summary(case):

    mappings = case.get("mitre_mappings", [])

    if not isinstance(mappings, list):
        mappings = []

    result = []

    for mapping in mappings:

        result.append({
            "technique_id": mapping.get("technique_id", "N/A"),
            "technique_name": mapping.get(
                "technique_name",
                mapping.get("technique", "N/A")
            ),
            "evidence": mapping.get(
                "evidence",
                mapping.get("event", "N/A")
            ),
            "count": mapping.get("count", "N/A"),
            "context": mapping.get("context", "N/A")
        })

    return result


# ============================================================
# ANALYST SUMMARY
# ============================================================

def build_analyst_summary(case):

    notes = case.get("analyst_notes", [])

    if not isinstance(notes, list):
        notes = []

    decisions = case.get("decision_history", [])

    if not isinstance(decisions, list):
        decisions = []

    activities = case.get("investigation_activity", [])

    if not isinstance(activities, list):
        activities = []

    return {
        "notes": notes,
        "decisions": decisions,
        "investigation_activity": activities,
        "current_decision": case.get("analyst_decision"),
        "decision_status": case.get("decision_status")
    }


# ============================================================
# RESPONSE SUMMARY
# ============================================================

def build_response_summary(case):

    actions = case.get("response_actions", [])

    if not isinstance(actions, list):
        actions = []

    action_summary = []

    for action in actions:

        action_summary.append({
            "action_id": action.get("action_id", "N/A"),
            "action": action.get("action", "N/A"),
            "status": action.get("status", "N/A"),
            "created_at": action.get("created_at", "N/A"),
            "updated_at": action.get("updated_at", "N/A"),
            "analyst_note": action.get(
                "analyst_note",
                ""
            )
        })

    completed = sum(
        1
        for action in actions
        if str(action.get("status", "")).upper()
        == "COMPLETED"
    )

    return {
        "total_actions": len(actions),
        "completed_actions": completed,
        "actions": action_summary
    }


# ============================================================
# RESOLUTION SUMMARY
# ============================================================

def build_resolution_summary(case):

    resolution = case.get("resolution", {})

    if not isinstance(resolution, dict):
        resolution = {}

    return {
        "status": case.get("status", "N/A"),
        "analyst_decision": case.get(
            "analyst_decision",
            "N/A"
        ),
        "resolution_reason": resolution.get(
            "reason",
            case.get("resolution_reason", "N/A")
        ),
        "resolved_at": resolution.get(
            "resolved_at",
            case.get("resolved_at", "N/A")
        )
    }


# ============================================================
# BUILD COMPLETE REPORT
# ============================================================

def build_report(case, alerts, correlations):

    generated_at = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    correlation = find_correlation(
        case,
        correlations
    )

    evidence = build_evidence_summary(
        case,
        correlation
    )

    detection = build_detection_summary(
        case,
        alerts
    )

    mitre = build_mitre_summary(
        case
    )

    analyst = build_analyst_summary(
        case
    )

    response = build_response_summary(
        case
    )

    resolution = build_resolution_summary(
        case
    )

    report_id = (
        "RPT-"
        + datetime.now().strftime("%Y%m%d%H%M%S")
    )

    report = {

        "report_id": report_id,

        "generated_at": generated_at,

        "report_type":
            "TRACEX_INCIDENT_INVESTIGATION_REPORT",

        "case_information": {
            "case_id": case.get("case_id"),
            "username": case.get("username"),
            "source_ip": case.get("source_ip"),
            "service": case.get("service"),
            "status": case.get("status"),
            "risk_score": case.get("risk_score"),
            "risk_level": case.get("risk_level"),
            "created_at": case.get("created_at"),
            "updated_at": case.get("updated_at")
        },

        "detection_summary":
            detection,

        "evidence_summary":
            evidence,

        "correlation_summary":
            correlation,

        "mitre_attack_context":
            mitre,

        "analyst_assessment":
            analyst,

        "response_summary":
            response,

        "resolution":
            resolution,

        "assessment": (
            "The report summarizes observed security events, "
            "correlated evidence, risk assessment, analyst "
            "activity, MITRE ATT&CK context, and response "
            "tracking. The presence of suspicious indicators "
            "does not by itself confirm malicious activity."
        )
    }

    return report


# ============================================================
# TEXT REPORT
# ============================================================

def generate_text_report(report):

    case = report["case_information"]
    evidence = report["evidence_summary"]
    detection = report["detection_summary"]
    mitre = report["mitre_attack_context"]
    analyst = report["analyst_assessment"]
    response = report["response_summary"]
    resolution = report["resolution"]

    lines = []

    lines.append("=" * 75)
    lines.append("                    TRACEX INCIDENT REPORT")
    lines.append("=" * 75)

    lines.append("")
    lines.append("REPORT INFORMATION")
    lines.append("-" * 75)

    lines.append(
        f"Report ID       : {report['report_id']}"
    )

    lines.append(
        f"Generated At    : {report['generated_at']}"
    )

    lines.append(
        f"Report Type     : {report['report_type']}"
    )

    lines.append("")
    lines.append("CASE INFORMATION")
    lines.append("-" * 75)

    lines.append(
        f"Case ID         : {safe(case.get('case_id'))}"
    )

    lines.append(
        f"Username        : {safe(case.get('username'))}"
    )

    lines.append(
        f"Source IP       : {safe(case.get('source_ip'))}"
    )

    lines.append(
        f"Service         : {safe(case.get('service'))}"
    )

    lines.append(
        f"Status          : {safe(case.get('status'))}"
    )

    lines.append(
        f"Risk Score      : {safe(case.get('risk_score'))}/100"
    )

    lines.append(
        f"Risk Level      : {safe(case.get('risk_level'))}"
    )

    lines.append("")
    lines.append("DETECTION SUMMARY")
    lines.append("-" * 75)

    lines.append(
        f"Related Alerts  : {detection['related_alert_count']}"
    )

    lines.append(
        "Detection Rules : "
        + (
            ", ".join(detection["detection_rules"])
            if detection["detection_rules"]
            else "None recorded"
        )
    )

    for alert in detection["related_alerts"]:

        lines.append(
            f"  • {alert['alert_id']} | "
            f"{alert['rule']} | "
            f"{alert['severity']}"
        )

    lines.append("")
    lines.append("EVIDENCE SUMMARY")
    lines.append("-" * 75)

    lines.append(
        f"Failed Logins       : "
        f"{evidence['failed_logins']}"
    )

    lines.append(
        f"Successful Logins   : "
        f"{evidence['successful_logins']}"
    )

    lines.append(
        f"Privileged Events   : "
        f"{evidence['sudo_events']}"
    )

    lines.append(
        f"Account Changes     : "
        f"{evidence['account_changes']}"
    )

    lines.append(
        f"Supporting Signals  : "
        f"{evidence['supporting_indicators']}"
    )

    for item in evidence["evidence"]:

        lines.append(
            f"  [+] {item['description']}"
        )

    lines.append("")
    lines.append("MITRE ATT&CK CONTEXT")
    lines.append("-" * 75)

    if mitre:

        for mapping in mitre:

            lines.append(
                f"  {mapping['technique_id']} - "
                f"{mapping['technique_name']}"
            )

            lines.append(
                f"      Evidence : "
                f"{mapping['evidence']}"
            )

            lines.append(
                f"      Context  : "
                f"{mapping['context']}"
            )

    else:

        lines.append(
            "  No MITRE ATT&CK mappings recorded."
        )

    lines.append("")
    lines.append("ANALYST ASSESSMENT")
    lines.append("-" * 75)

    lines.append(
        f"Current Decision : "
        f"{safe(analyst.get('current_decision'))}"
    )

    lines.append(
        f"Decision Status  : "
        f"{safe(analyst.get('decision_status'))}"
    )

    lines.append(
        f"Analyst Notes    : "
        f"{len(analyst['notes'])}"
    )

    lines.append(
        f"Investigation Activities : "
        f"{len(analyst['investigation_activity'])}"
    )

    for note in analyst["notes"]:

        lines.append(
            f"  • {safe(note.get('timestamp'))} "
            f"- {safe(note.get('note'))}"
        )

    lines.append("")
    lines.append("RESPONSE ACTIONS")
    lines.append("-" * 75)

    lines.append(
        f"Total Actions     : "
        f"{response['total_actions']}"
    )

    lines.append(
        f"Completed Actions : "
        f"{response['completed_actions']}"
    )

    for action in response["actions"]:

        lines.append(
            f"  • {action['action']} "
            f"[{action['status']}]"
        )

    lines.append("")
    lines.append("RESOLUTION")
    lines.append("-" * 75)

    lines.append(
        f"Status           : "
        f"{safe(resolution.get('status'))}"
    )

    lines.append(
        f"Analyst Decision : "
        f"{safe(resolution.get('analyst_decision'))}"
    )

    lines.append(
        f"Resolution Reason: "
        f"{safe(resolution.get('resolution_reason'))}"
    )

    lines.append(
        f"Resolved At      : "
        f"{safe(resolution.get('resolved_at'))}"
    )

    lines.append("")
    lines.append("ASSESSMENT")
    lines.append("-" * 75)

    lines.append(
        report["assessment"]
    )

    lines.append("")
    lines.append("=" * 75)
    lines.append("                  END OF TRACEX REPORT")
    lines.append("=" * 75)

    return "\n".join(lines)


# ============================================================
# SAVE REPORT
# ============================================================

def save_report(report):

    os.makedirs(
        REPORTS_DIR,
        exist_ok=True
    )

    report_id = report["report_id"]

    json_path = os.path.join(
        REPORTS_DIR,
        f"{report_id}.json"
    )

    txt_path = os.path.join(
        REPORTS_DIR,
        f"{report_id}.txt"
    )

    json_saved = save_json(
        json_path,
        report
    )

    text_report = generate_text_report(
        report
    )

    try:

        with open(txt_path, "w") as f:
            f.write(text_report)

        text_saved = True

    except OSError:

        text_saved = False

    return json_saved and text_saved, json_path, txt_path


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 75)
    print("                 TRACEX INCIDENT REPORT GENERATOR")
    print("=" * 75)

    cases = as_list(
        load_json(
            CASES_FILE,
            []
        )
    )

    alerts = as_list(
        load_json(
            ALERTS_FILE,
            []
        )
    )

    correlations = as_list(
        load_json(
            CORRELATION_FILE,
            []
        )
    )

    if not cases:

        print()
        print("[!] No cases available.")
        print("[i] Create an investigation case first.")
        return

    print()
    print(
        f"[+] Cases loaded        : {len(cases)}"
    )

    print(
        f"[+] Alerts loaded       : {len(alerts)}"
    )

    print(
        f"[+] Correlations loaded : {len(correlations)}"
    )

    print()

    print("Available Cases:")
    print("-" * 75)

    for case in cases:

        print(
            f"{case.get('case_id')} | "
            f"{case.get('username')} | "
            f"{case.get('source_ip')} | "
            f"Risk: {case.get('risk_score', 'N/A')}/100 | "
            f"Status: {case.get('status', 'N/A')}"
        )

    print("-" * 75)

    case_id = input(
        "\nEnter Case ID: "
    ).strip()

    case = next(
        (
            c for c in cases
            if c.get("case_id") == case_id
        ),
        None
    )

    if not case:

        print()
        print(
            f"[!] Case not found: {case_id}"
        )
        return

    print()
    print(
        "[+] Building incident report..."
    )

    report = build_report(
        case,
        alerts,
        correlations
    )

    success, json_path, txt_path = save_report(
        report
    )

    if not success:

        print()
        print("[!] Failed to save report.")
        return

    print()
    print("=" * 75)
    print("                 REPORT GENERATED")
    print("=" * 75)

    print(
        f"Report ID       : "
        f"{report['report_id']}"
    )

    print(
        f"Case ID         : "
        f"{case.get('case_id')}"
    )

    print(
        f"Risk            : "
        f"{case.get('risk_score', 'N/A')}/100 "
        f"({case.get('risk_level', 'N/A')})"
    )

    print(
        f"JSON Report     : "
        f"{json_path}"
    )

    print(
        f"Text Report     : "
        f"{txt_path}"
    )

    print()
    print(
        "[✓] Incident report generated successfully."
    )

    print("=" * 75)


if __name__ == "__main__":
    main()
