import json
import os
from datetime import datetime


CASES_FILE = "alerts/cases.json"


# ============================================================
# JSON HELPERS
# ============================================================

def load_cases():
    """Load cases from cases.json."""

    if not os.path.exists(CASES_FILE):
        return []

    try:
        with open(CASES_FILE, "r") as f:
            data = json.load(f)

        if isinstance(data, list):
            return data

        return []

    except (json.JSONDecodeError, OSError):
        return []


def save_cases(cases):
    """Save cases back to cases.json."""

    with open(CASES_FILE, "w") as f:
        json.dump(cases, f, indent=4)


# ============================================================
# EVIDENCE ANALYSIS
# ============================================================

def evaluate_evidence(case):
    """
    Evaluate the evidence currently stored in a case.

    This does NOT confirm malicious activity.
    It determines whether the case contains enough
    correlated evidence to support continued investigation.
    """

    event_counts = case.get(
        "event_counts",
        {}
    )

    failed_logins = int(
        event_counts.get(
            "failed_logins",
            0
        )
    )

    successful_logins = int(
        event_counts.get(
            "successful_logins",
            0
        )
    )

    sudo_events = int(
        event_counts.get(
            "sudo_events",
            0
        )
    )

    account_changes = int(
        event_counts.get(
            "account_changes",
            0
        )
    )

    evidence_points = 0
    reasons = []

    # --------------------------------------------------------
    # FAILED AUTHENTICATION
    # --------------------------------------------------------

    if failed_logins >= 5:

        evidence_points += 1

        reasons.append(
            f"{failed_logins} failed authentication attempts"
        )

    elif failed_logins > 0:

        reasons.append(
            f"{failed_logins} failed authentication attempt(s)"
        )

    # --------------------------------------------------------
    # SUCCESS AFTER FAILURES
    # --------------------------------------------------------

    if (
        failed_logins > 0
        and successful_logins > 0
    ):

        evidence_points += 1

        reasons.append(
            "Successful authentication occurred "
            "after failed authentication activity"
        )

    elif successful_logins > 0:

        reasons.append(
            f"{successful_logins} successful authentication event(s)"
        )

    # --------------------------------------------------------
    # PRIVILEGED ACTIVITY
    # --------------------------------------------------------

    if sudo_events > 0:

        evidence_points += 1

        reasons.append(
            f"{sudo_events} privileged activity event(s)"
        )

    # --------------------------------------------------------
    # ACCOUNT MODIFICATION
    # --------------------------------------------------------

    if account_changes > 0:

        evidence_points += 1

        reasons.append(
            f"{account_changes} account modification event(s)"
        )

    # --------------------------------------------------------
    # DETERMINE EVIDENCE STATUS
    # --------------------------------------------------------

    if evidence_points >= 3:

        evidence_status = (
            "STRONG_CORRELATED_EVIDENCE"
        )

        recommendation = (
            "Continue investigation and review "
            "response actions."
        )

    elif evidence_points >= 1:

        evidence_status = (
            "RELEVANT_EVIDENCE"
        )

        recommendation = (
            "Continue investigation and validate "
            "the observed activity."
        )

    else:

        evidence_status = (
            "INSUFFICIENT_EVIDENCE"
        )

        recommendation = (
            "Insufficient correlated evidence. "
            "Keep the case open for further review."
        )

    return {
        "evidence_points": evidence_points,
        "evidence_status": evidence_status,
        "reasons": reasons,
        "recommendation": recommendation
    }


# ============================================================
# CASE RESOLUTION DECISION
# ============================================================

def get_resolution_assessment(case):
    """
    Generate an analyst-oriented resolution assessment.

    The engine does not automatically claim that an attack
    occurred. It only evaluates the available evidence.
    """

    evidence = evaluate_evidence(case)

    risk_score = int(
        case.get(
            "risk_score",
            0
        )
    )

    risk_level = case.get(
        "risk_level",
        "LOW"
    )

    if (
        evidence["evidence_status"]
        == "STRONG_CORRELATED_EVIDENCE"
    ):

        recommended_status = "INVESTIGATING"

        assessment = (
            "Strong correlated evidence is present. "
            "The case should remain under investigation "
            "until an analyst completes evidence review "
            "and response validation."
        )

    elif (
        evidence["evidence_status"]
        == "RELEVANT_EVIDENCE"
    ):

        recommended_status = "INVESTIGATING"

        assessment = (
            "Relevant security evidence is present. "
            "Further analyst validation is recommended."
        )

    else:

        recommended_status = "NEW"

        assessment = (
            "Current evidence is insufficient for "
            "a strong investigation conclusion."
        )

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "evidence_points": evidence[
            "evidence_points"
        ],
        "evidence_status": evidence[
            "evidence_status"
        ],
        "evidence_reasons": evidence[
            "reasons"
        ],
        "recommendation": evidence[
            "recommendation"
        ],
        "recommended_status": recommended_status,
        "assessment": assessment
    }


# ============================================================
# DISPLAY CASE ASSESSMENT
# ============================================================

def display_assessment(case):
    """Display detailed resolution assessment."""

    result = get_resolution_assessment(
        case
    )

    print("\n" + "=" * 70)

    print(
        "             TRACEX CASE RESOLUTION ASSESSMENT"
    )

    print("=" * 70)

    print(
        f"\nCase ID       : "
        f"{case.get('case_id', 'N/A')}"
    )

    print(
        f"Current Status: "
        f"{case.get('status', 'N/A')}"
    )

    print(
        f"Risk Score    : "
        f"{result['risk_score']}/100"
    )

    print(
        f"Risk Level    : "
        f"{result['risk_level']}"
    )

    print(
        f"Evidence      : "
        f"{result['evidence_points']} supporting indicators"
    )

    print(
        f"Evidence Status: "
        f"{result['evidence_status']}"
    )

    print("\nEvidence:")

    if result["evidence_reasons"]:

        for reason in result[
            "evidence_reasons"
        ]:

            print(
                f"  [+] {reason}"
            )

    else:

        print(
            "  [-] No significant correlated evidence."
        )

    print("\nAssessment:")

    print(
        f"  {result['assessment']}"
    )

    print("\nRecommendation:")

    print(
        f"  {result['recommendation']}"
    )

    print(
        f"\nRecommended Status: "
        f"{result['recommended_status']}"
    )

    print("=" * 70)


# ============================================================
# FIND ACTIVE CASES
# ============================================================

def get_active_cases(cases):
    """
    Return cases that are not archived.
    """

    return [
        case
        for case in cases
        if case.get("status") != "ARCHIVED"
    ]


# ============================================================
# RESOLVE CASE
# ============================================================

def resolve_case(case_id):
    """
    Resolve a case only when the analyst explicitly
    requests resolution.

    The engine does not automatically resolve cases.
    """

    cases = load_cases()

    for case in cases:

        if case.get("case_id") == case_id:

            current_status = case.get(
                "status",
                "NEW"
            )

            if current_status == "ARCHIVED":

                print(
                    f"{case_id} is archived and "
                    "cannot be resolved."
                )

                return

            if current_status == "RESOLVED":

                print(
                    f"{case_id} is already resolved."
                )

                return

            now = datetime.now().isoformat(
                timespec="seconds"
            )

            case["status"] = "RESOLVED"

            case["updated_at"] = now

            case["resolution"] = {
                "resolved_at": now,
                "resolution_reason":
                    "Case resolved by analyst after evidence review."
            }

            save_cases(cases)

            print(
                f"\n{case_id} has been marked RESOLVED."
            )

            return

    print(
        f"Case {case_id} not found."
    )


# ============================================================
# MAIN
# ============================================================

def main():

    cases = load_cases()

    if not cases:

        print(
            "No cases found."
        )

        return

    print(
        "\n" + "=" * 70
    )

    print(
        "             TRACEX CASE RESOLUTION ENGINE"
    )

    print(
        "=" * 70
    )

    # --------------------------------------------------------
    # SHOW CASE LIST
    # --------------------------------------------------------

    print("\nAvailable Cases:\n")

    for case in cases:

        case_id = case.get(
            "case_id",
            "N/A"
        )

        status = case.get(
            "status",
            "N/A"
        )

        risk = case.get(
            "risk_level",
            "LOW"
        )

        print(
            f"{case_id} | "
            f"{status} | "
            f"Risk: {risk}"
        )

    # --------------------------------------------------------
    # ANALYZE ACTIVE CASES
    # --------------------------------------------------------

    active_cases = get_active_cases(
        cases
    )

    if not active_cases:

        print(
            "\nNo active cases available."
        )

        return

    print(
        "\n" + "-" * 70
    )

    print(
        "ACTIVE CASE ASSESSMENTS"
    )

    print(
        "-" * 70
    )

    for case in active_cases:

        display_assessment(
            case
        )


# ============================================================
# PROGRAM ENTRY
# ============================================================

if __name__ == "__main__":

    main()
