import json
import os
from datetime import datetime

from investigation.case_resolver import find_canonical_case


CASES_FILE = "alerts/cases.json"
CORRELATION_FILE = "alerts/correlation_results.json"


# ============================================================
# JSON HELPERS
# ============================================================

def load_json(file_path, default):
    """
    Load JSON data from a file.

    Returns default value if:
    - file does not exist
    - JSON is invalid
    - file cannot be read
    """

    if not os.path.exists(file_path):
        return default

    try:
        with open(file_path, "r") as f:
            return json.load(f)

    except (json.JSONDecodeError, OSError):
        return default


def save_cases(cases):
    """Save all cases to cases.json."""

    with open(CASES_FILE, "w") as f:
        json.dump(cases, f, indent=4)


# ============================================================
# GENERAL HELPERS
# ============================================================

def normalize_list(value):
    """
    Convert a value into a list.

    Examples:
        None       -> []
        "TRX-0001" -> ["TRX-0001"]
        ["A", "B"] -> ["A", "B"]
    """

    if value is None:
        return []

    if isinstance(value, list):
        return value

    return [value]


def get_next_case_id(cases):
    """
    Generate the next CASE-XXXX identifier.
    """

    numbers = []

    for case in cases:

        case_id = case.get("case_id", "")

        if case_id.startswith("CASE-"):

            try:
                number = int(case_id.split("-")[1])
                numbers.append(number)

            except (ValueError, IndexError):
                pass

    next_number = max(numbers, default=0) + 1

    return f"CASE-{next_number:04d}"


# ============================================================
# CASE CREATION
# ============================================================

def build_case_from_correlation(correlation):
    """
    Create a new case from correlation data.
    """

    now = datetime.now().isoformat(
        timespec="seconds"
    )

    username = correlation.get("username")
    source_ip = correlation.get("source_ip")

    related_alert_ids = normalize_list(
        correlation.get("related_alert_ids")
        or correlation.get("alert_ids")
    )

    detection_rules = normalize_list(
        correlation.get("detection_rules")
    )

    event_counts = correlation.get(
        "event_counts",
        {}
    )

    risk_score = correlation.get(
        "risk_score",
        0
    )

    risk_level = correlation.get(
        "risk_level",
        "LOW"
    )

    return {

        "case_id": None,

        "created_at": now,

        "updated_at": now,

        "status": "NEW",

        "risk_score": risk_score,

        "risk_level": risk_level,

        "username": username,

        "source_ip": source_ip,

        "related_alert_ids": related_alert_ids,

        "detection_rules": detection_rules,

        "event_counts": event_counts,

        "analyst_notes": [],

        "mitre_mappings": [],

        "response_actions": [],

        "timeline": [],

        "correlation_reason":
            "Automatically generated from correlated security events."
    }


# ============================================================
# EXISTING CASE UPDATE
# ============================================================

def update_existing_case(case, correlation):
    """
    Update an existing canonical case with
    newly correlated information.
    """

    now = datetime.now().isoformat(
        timespec="seconds"
    )

    case["updated_at"] = now

    # --------------------------------------------------------
    # UPDATE IDENTITY
    # --------------------------------------------------------

    if correlation.get("username"):

        case["username"] = correlation.get(
            "username"
        )

    if correlation.get("source_ip"):

        case["source_ip"] = correlation.get(
            "source_ip"
        )

    # --------------------------------------------------------
    # MERGE ALERT IDS
    # --------------------------------------------------------

    existing_alerts = set(
        normalize_list(
            case.get("related_alert_ids")
        )
    )

    new_alerts = set(
        normalize_list(
            correlation.get("related_alert_ids")
            or correlation.get("alert_ids")
        )
    )

    case["related_alert_ids"] = sorted(
        existing_alerts | new_alerts
    )

    # --------------------------------------------------------
    # MERGE DETECTION RULES
    # --------------------------------------------------------

    existing_rules = set(
        normalize_list(
            case.get("detection_rules")
        )
    )

    new_rules = set(
        normalize_list(
            correlation.get("detection_rules")
        )
    )

    case["detection_rules"] = sorted(
        existing_rules | new_rules
    )

    # --------------------------------------------------------
    # UPDATE EVENT COUNTS
    # --------------------------------------------------------

    existing_counts = case.get(
        "event_counts",
        {}
    )

    new_counts = correlation.get(
        "event_counts",
        {}
    )

    for key, value in new_counts.items():

        try:
            value = int(value)

        except (TypeError, ValueError):
            continue

        old_value = int(
            existing_counts.get(
                key,
                0
            )
        )

        # Keep the highest observed count.
        existing_counts[key] = max(
            old_value,
            value
        )

    case["event_counts"] = existing_counts

    # --------------------------------------------------------
    # UPDATE RISK
    # --------------------------------------------------------

    new_risk = correlation.get(
        "risk_score"
    )

    if new_risk is not None:

        try:

            new_risk = int(new_risk)

            old_risk = int(
                case.get(
                    "risk_score",
                    0
                )
            )

            if new_risk > old_risk:

                case["risk_score"] = new_risk

                case["risk_level"] = correlation.get(
                    "risk_level",
                    case.get(
                        "risk_level",
                        "LOW"
                    )
                )

        except (TypeError, ValueError):

            pass

    # --------------------------------------------------------
    # UPDATE CORRELATION REASON
    # --------------------------------------------------------

    if correlation.get("correlation_reason"):

        case["correlation_reason"] = (
            correlation.get(
                "correlation_reason"
            )
        )

    return case


# ============================================================
# CASE SYNCHRONIZATION
# ============================================================

def synchronize_case():

    # --------------------------------------------------------
    # LOAD CASES
    # --------------------------------------------------------

    cases = load_json(
        CASES_FILE,
        []
    )

    # --------------------------------------------------------
    # LOAD CORRELATION RESULTS
    # --------------------------------------------------------

    correlation_data = load_json(
        CORRELATION_FILE,
        []
    )

    if not correlation_data:

        print(
            "No correlation data found."
        )

        return

    # --------------------------------------------------------
    # SUPPORT BOTH JSON FORMATS
    #
    # FORMAT 1:
    # {
    #     "username": "...",
    #     ...
    # }
    #
    # FORMAT 2:
    # [
    #     {
    #         "username": "...",
    #         ...
    #     }
    # ]
    # --------------------------------------------------------

    if isinstance(
        correlation_data,
        dict
    ):

        correlation_groups = [
            correlation_data
        ]

    elif isinstance(
        correlation_data,
        list
    ):

        correlation_groups = (
            correlation_data
        )

    else:

        print(
            "Invalid correlation data format."
        )

        return

    # --------------------------------------------------------
    # HEADER
    # --------------------------------------------------------

    print(
        "\n========== TRACEX CASE SYNCHRONIZATION =========="
    )

    print(
        f"Correlation groups : "
        f"{len(correlation_groups)}"
    )

    total_created = 0
    total_updated = 0
    total_skipped = 0

    # ========================================================
    # PROCESS EACH CORRELATION GROUP
    # ========================================================

    for group_number, correlation in enumerate(
        correlation_groups,
        start=1
    ):

        # ----------------------------------------------------
        # VALIDATE GROUP
        # ----------------------------------------------------

        if not isinstance(
            correlation,
            dict
        ):

            print(
                f"\nSkipping invalid "
                f"correlation group "
                f"{group_number}."
            )

            total_skipped += 1

            continue

        # ----------------------------------------------------
        # EXTRACT IDENTITY
        # ----------------------------------------------------

        username = correlation.get(
            "username"
        )

        source_ip = correlation.get(
            "source_ip"
        )

        # ----------------------------------------------------
        # EXTRACT ALERT IDS
        # ----------------------------------------------------

        alert_ids = normalize_list(
            correlation.get(
                "related_alert_ids"
            )
            or correlation.get(
                "alert_ids"
            )
        )

        # ----------------------------------------------------
        # DISPLAY GROUP
        # ----------------------------------------------------

        print(
            f"\n----- Correlation Group "
            f"{group_number} -----"
        )

        print(
            f"Username    : {username}"
        )

        print(
            f"Source IP   : {source_ip}"
        )

        if alert_ids:

            print(
                "Alert IDs   : "
                + ", ".join(
                    str(alert_id)
                    for alert_id in alert_ids
                )
            )

        else:

            print(
                "Alert IDs   : None"
            )

        # ====================================================
        # FIND CANONICAL CASE
        # ====================================================

        canonical_case = find_canonical_case(

            username=username,

            source_ip=source_ip,

            alert_ids=alert_ids
        )

        # ====================================================
        # EXISTING CASE FOUND
        # ====================================================

        if canonical_case:

            canonical_id = (
                canonical_case.get(
                    "case_id"
                )
            )

            print(
                f"\nExisting related case found: "
                f"{canonical_id}"
            )

            case_updated = False

            # ------------------------------------------------
            # FIND CASE IN LOCAL CASE LIST
            # ------------------------------------------------

            for index, case in enumerate(
                cases
            ):

                if case.get(
                    "case_id"
                ) == canonical_id:

                    # ----------------------------------------
                    # UPDATE EXISTING CASE
                    # ----------------------------------------

                    cases[index] = (
                        update_existing_case(
                            case,
                            correlation
                        )
                    )

                    case_updated = True

                    total_updated += 1

                    print(
                        "Action      : UPDATED"
                    )

                    print(
                        "Duplicate case "
                        "creation prevented."
                    )

                    break

            # ------------------------------------------------
            # CANONICAL CASE NOT FOUND IN LOCAL LIST
            # ------------------------------------------------

            if not case_updated:

                print(
                    "Warning: canonical case "
                    "was found by resolver "
                    "but could not be updated."
                )

                total_skipped += 1

        # ====================================================
        # NO EXISTING CASE → CREATE NEW CASE
        # ====================================================

        else:

            new_case = (
                build_case_from_correlation(
                    correlation
                )
            )

            new_case["case_id"] = (
                get_next_case_id(
                    cases
                )
            )

            cases.append(
                new_case
            )

            total_created += 1

            print(
                "\nNo existing related "
                "case found."
            )

            print(
                f"New Case    : "
                f"{new_case['case_id']}"
            )

            print(
                "Action      : CREATED"
            )

    # ========================================================
    # SAVE CASE DATABASE
    # ========================================================

    save_cases(
        cases
    )

    # ========================================================
    # FINAL SUMMARY
    # ========================================================

    print(
        "\n========== SYNCHRONIZATION SUMMARY =========="
    )

    print(
        f"Cases updated : "
        f"{total_updated}"
    )

    print(
        f"Cases created : "
        f"{total_created}"
    )

    print(
        f"Cases skipped : "
        f"{total_skipped}"
    )

    print(
        f"Total cases   : "
        f"{len(cases)}"
    )

    print(
        "=============================================\n"
    )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    synchronize_case()
