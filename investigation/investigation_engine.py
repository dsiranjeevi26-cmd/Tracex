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


def load_json(path):
    if not os.path.exists(path):
        return []

    try:
        with open(path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def normalize_data(data):
    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        return [data]

    return []


def find_case(cases, case_id):
    for case in cases:
        if case.get("case_id") == case_id:
            return case

    return None


def find_correlations(correlations, username, source_ip):
    matches = []

    for correlation in correlations:
        if (
            correlation.get("username") == username
            and correlation.get("source_ip") == source_ip
        ):
            matches.append(correlation)

    return matches


def extract_evidence(case, correlations):
    """
    Build evidence from correlation data.

    Correlation data is treated as the primary source
    for event counts and related alerts.
    """

    username = case.get("username", "unknown")
    source_ip = case.get("source_ip", "unknown")

    matches = find_correlations(
        correlations,
        username,
        source_ip
    )

    evidence = {
        "failed_logins": 0,
        "successful_logins": 0,
        "sudo_events": 0,
        "account_changes": 0
    }

    related_alerts = []
    services = []
    timeline = []

    for correlation in matches:

        counts = correlation.get("event_counts", {})

        evidence["failed_logins"] += counts.get(
            "failed_logins",
            0
        )

        evidence["successful_logins"] += counts.get(
            "successful_logins",
            0
        )

        evidence["sudo_events"] += counts.get(
            "sudo_events",
            0
        )

        evidence["account_changes"] += counts.get(
            "account_changes",
            0
        )

        for alert_id in correlation.get(
            "related_alerts",
            []
        ):
            if alert_id not in related_alerts:
                related_alerts.append(alert_id)

        service = correlation.get("primary_service")

        if service and service not in services:
            services.append(service)

        for event in correlation.get(
            "timeline",
            []
        ):
            timeline.append(event)

    return evidence, related_alerts, services, timeline


def build_investigation(case, correlations):

    username = case.get(
        "username",
        "unknown"
    )

    source_ip = case.get(
        "source_ip",
        "unknown"
    )

    evidence, related_alerts, services, timeline = (
        extract_evidence(
            case,
            correlations
        )
    )

    # Prefer correlation service.
    # Fall back to case service if available.
    if services:
        service = services[0]
    else:
        service = case.get(
            "service",
            "unknown"
        )

    # Prefer the risk already synchronized
    # into the case.
    risk_score = case.get(
        "risk_score",
        0
    )

    risk_level = case.get(
        "risk_level",
        "LOW"
    )

    investigation = {

        "investigation_id":
            f"INV-{datetime.now().strftime('%Y%m%d%H%M%S')}",

        "case_id":
            case.get("case_id"),

        "created_at":
            datetime.now().isoformat(),

        "subject": {
            "username": username,
            "source_ip": source_ip,
            "service": service
        },

        "case_status":
            case.get(
                "status",
                "NEW"
            ),

        "risk": {
            "score": risk_score,
            "level": risk_level
        },

        "evidence": evidence,

        "related_alerts":
            related_alerts,

        "timeline":
            timeline,

        "analyst_assessment": (
            "Evidence has been correlated for "
            "analyst review. Automated analysis "
            "does not confirm malicious activity."
        ),

        "recommended_next_step": (
            "Review authentication activity, "
            "privileged actions, and account "
            "changes before making an incident decision."
        )
    }

    return investigation


def display_investigation(investigation):

    print("\n" + "=" * 60)
    print("          TRACEX INVESTIGATION ENGINE")
    print("=" * 60)

    print(
        f"\nInvestigation ID : "
        f"{investigation['investigation_id']}"
    )

    print(
        f"Case ID         : "
        f"{investigation['case_id']}"
    )

    subject = investigation["subject"]

    print("\n--- SUBJECT ---")

    print(
        f"Username        : "
        f"{subject['username']}"
    )

    print(
        f"Source IP       : "
        f"{subject['source_ip']}"
    )

    print(
        f"Service         : "
        f"{subject['service']}"
    )

    risk = investigation["risk"]

    print("\n--- RISK ---")

    print(
        f"Risk Score      : "
        f"{risk['score']}/100"
    )

    print(
        f"Risk Level      : "
        f"{risk['level']}"
    )

    evidence = investigation["evidence"]

    print("\n--- EVIDENCE SUMMARY ---")

    print(
        f"Failed Logins   : "
        f"{evidence['failed_logins']}"
    )

    print(
        f"Successful      : "
        f"{evidence['successful_logins']}"
    )

    print(
        f"Sudo Events     : "
        f"{evidence['sudo_events']}"
    )

    print(
        f"Account Changes : "
        f"{evidence['account_changes']}"
    )

    print("\n--- RELATED ALERTS ---")

    alerts = investigation[
        "related_alerts"
    ]

    if alerts:

        for alert in alerts:
            print(
                f"  • {alert}"
            )

    else:
        print("  None")

    print("\n--- TIMELINE ---")

    timeline = investigation[
        "timeline"
    ]

    if timeline:

        for event in timeline:

            print(
                f"  • {event}"
            )

    else:

        print(
            "  No correlated timeline available."
        )

    print("\n--- ANALYST ASSESSMENT ---")

    print(
        investigation[
            "analyst_assessment"
        ]
    )

    print("\n--- RECOMMENDED NEXT STEP ---")

    print(
        investigation[
            "recommended_next_step"
        ]
    )

    print("\n" + "=" * 60)


def main():

    cases_data = load_json(
        CASES_FILE
    )

    correlation_data = load_json(
        CORRELATION_FILE
    )

    cases = normalize_data(
        cases_data
    )

    correlations = normalize_data(
        correlation_data
    )

    if not cases:

        print(
            "[!] No cases available "
            "for investigation."
        )

        return

    print("\nAvailable Cases:")

    for case in cases:

        print(
            f"  {case.get('case_id', 'UNKNOWN')} | "
            f"{case.get('username', 'unknown')} | "
            f"{case.get('source_ip', 'unknown')} | "
            f"Risk: "
            f"{case.get('risk_score', 0)}/100 "
            f"{case.get('risk_level', 'LOW')}"
        )

    case_id = input(
        "\nEnter Case ID to investigate: "
    ).strip()

    case = find_case(
        cases,
        case_id
    )

    if not case:

        print(
            "[!] Case not found."
        )

        return

    investigation = build_investigation(
        case,
        correlations
    )

    display_investigation(
        investigation
    )


if __name__ == "__main__":
    main()
