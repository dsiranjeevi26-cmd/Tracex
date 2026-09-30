import json
import os
from datetime import datetime


CASES_FILE = "alerts/cases.json"


def load_json(path, default):
    if not os.path.exists(path):
        return default

    try:
        with open(path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return default


def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)


def get_case_alert_ids(case):
    """
    Collect every alert ID associated with a case.
    """

    alert_ids = set()

    alert_id = case.get("alert_id")

    if alert_id:
        alert_ids.add(alert_id)

    for alert in case.get("related_alert_ids", []):
        if alert:
            alert_ids.add(alert)

    for alert in case.get("alert_ids", []):
        if alert:
            alert_ids.add(alert)

    return alert_ids


def get_identity(case):
    """
    Return username/source identity when available.
    """

    username = case.get("username")
    source_ip = case.get("source_ip")

    if username and source_ip:
        return username, source_ip

    return None


def evidence_score(case):
    counts = case.get("event_counts", {})

    return (
        counts.get("failed_logins", 0)
        + counts.get("successful_logins", 0)
        + counts.get("sudo_events", 0)
        + counts.get("account_changes", 0)
    )


def risk_score(case):
    return case.get("risk_score", 0) or 0


def case_priority(case):
    """
    Decide which case should become canonical.
    """

    status = case.get("status", "NEW")

    investigating_bonus = 1000 if status == "INVESTIGATING" else 0

    return (
        investigating_bonus
        + evidence_score(case) * 10
        + risk_score(case)
        + len(get_case_alert_ids(case))
    )


def merge_unique_list(destination, source):
    if not isinstance(destination, list):
        destination = []

    if not isinstance(source, list):
        return destination

    for item in source:
        if item not in destination:
            destination.append(item)

    return destination


def merge_response_actions(canonical, duplicate):
    """
    Preserve analyst response actions.
    """

    canonical["response_actions"] = merge_unique_list(
        canonical.get("response_actions", []),
        duplicate.get("response_actions", [])
    )


def merge_analyst_notes(canonical, duplicate):
    """
    Preserve analyst notes.
    """

    canonical["analyst_notes"] = merge_unique_list(
        canonical.get("analyst_notes", []),
        duplicate.get("analyst_notes", [])
    )


def merge_alerts(canonical, duplicate):
    """
    Merge alert references.
    """

    canonical["related_alert_ids"] = merge_unique_list(
        canonical.get("related_alert_ids", []),
        list(get_case_alert_ids(duplicate))
    )


def merge_mitre(canonical, duplicate):
    """
    Preserve MITRE mappings without duplication.
    """

    existing = canonical.get("mitre_mappings", [])

    for mapping in duplicate.get("mitre_mappings", []):

        technique_id = mapping.get("technique_id")

        already_exists = any(
            item.get("technique_id") == technique_id
            for item in existing
        )

        if not already_exists:
            existing.append(mapping)

    canonical["mitre_mappings"] = existing


def merge_event_counts(canonical, duplicate):
    """
    Keep the strongest observed count for each evidence category.
    """

    canonical_counts = canonical.get("event_counts", {})
    duplicate_counts = duplicate.get("event_counts", {})

    for key, value in duplicate_counts.items():

        if not isinstance(value, (int, float)):
            continue

        current = canonical_counts.get(key, 0)

        if value > current:
            canonical_counts[key] = value

    canonical["event_counts"] = canonical_counts


def merge_detection_rules(canonical, duplicate):
    canonical["detection_rules"] = merge_unique_list(
        canonical.get("detection_rules", []),
        duplicate.get("detection_rules", [])
    )


def merge_case(canonical, duplicate):
    """
    Merge useful information from a duplicate case.
    """

    merge_response_actions(canonical, duplicate)

    merge_analyst_notes(canonical, duplicate)

    merge_alerts(canonical, duplicate)

    merge_mitre(canonical, duplicate)

    merge_event_counts(canonical, duplicate)

    merge_detection_rules(canonical, duplicate)

    # Preserve the highest risk score.
    if risk_score(duplicate) > risk_score(canonical):
        canonical["risk_score"] = duplicate["risk_score"]

    # Recalculate risk level.
    score = canonical.get("risk_score", 0)

    if score >= 80:
        canonical["risk_level"] = "HIGH"
    elif score >= 50:
        canonical["risk_level"] = "MEDIUM"
    else:
        canonical["risk_level"] = "LOW"

    # Keep consolidation history.
    canonical["consolidated_from"] = merge_unique_list(
        canonical.get("consolidated_from", []),
        [duplicate.get("case_id")]
    )

    # Preserve previous resolution as historical information.
    if duplicate.get("resolution"):

        historical_resolution = canonical.get(
            "historical_resolutions",
            []
        )

        historical_resolution.append({
            "case_id": duplicate.get("case_id"),
            "resolution": duplicate.get("resolution")
        })

        canonical["historical_resolutions"] = historical_resolution

    canonical["last_consolidated_at"] = datetime.now().isoformat()


def cases_are_related(case_a, case_b):
    """
    Determine whether two cases represent the same investigation.
    """

    # ---------------------------------------
    # Method 1: Same username + source IP
    # ---------------------------------------

    identity_a = get_identity(case_a)
    identity_b = get_identity(case_b)

    if identity_a and identity_b:
        if identity_a == identity_b:
            return True

    # ---------------------------------------
    # Method 2: Alert relationship
    # ---------------------------------------

    alerts_a = get_case_alert_ids(case_a)
    alerts_b = get_case_alert_ids(case_b)

    if alerts_a.intersection(alerts_b):
        return True

    return False


def consolidate_cases():

    print("\n========== TRACEX CASE CONSOLIDATION ==========\n")

    cases = load_json(CASES_FILE, [])

    if not cases:
        print("[!] No cases found.")
        return

    print(f"Cases loaded : {len(cases)}")

    active_cases = [
        case
        for case in cases
        if case.get("status") != "ARCHIVED"
    ]

    print(f"Active cases : {len(active_cases)}")

    processed = set()

    groups = []

    # ---------------------------------------
    # Build related-case groups
    # ---------------------------------------

    for case in active_cases:

        case_id = case.get("case_id")

        if case_id in processed:
            continue

        group = [case]

        changed = True

        while changed:

            changed = False

            for candidate in active_cases:

                candidate_id = candidate.get("case_id")

                if candidate_id in {
                    item.get("case_id")
                    for item in group
                }:
                    continue

                for existing in group:

                    if cases_are_related(candidate, existing):

                        group.append(candidate)
                        changed = True
                        break

        for item in group:
            processed.add(item.get("case_id"))

        groups.append(group)

    consolidated_count = 0
    archived_count = 0

    # ---------------------------------------
    # Consolidate duplicate groups
    # ---------------------------------------

    for group in groups:

        if len(group) <= 1:
            continue

        print("\n--------------------------------------------")
        print("Related investigation cases detected")

        print(
            "Cases :",
            ", ".join(
                case.get("case_id")
                for case in group
            )
        )

        # Choose canonical case.
        canonical = max(
            group,
            key=case_priority
        )

        canonical_id = canonical.get("case_id")

        print(f"Canonical case : {canonical_id}")

        for duplicate in group:

            duplicate_id = duplicate.get("case_id")

            if duplicate_id == canonical_id:
                continue

            print(
                f"  Merging {duplicate_id} "
                f"→ {canonical_id}"
            )

            merge_case(
                canonical,
                duplicate
            )

            duplicate["status"] = "ARCHIVED"

            duplicate["archived_at"] = (
                datetime.now().isoformat()
            )

            duplicate["archived_reason"] = (
                f"Consolidated into {canonical_id}"
            )

            duplicate["canonical_case_id"] = canonical_id

            archived_count += 1

        consolidated_count += 1

    save_json(
        CASES_FILE,
        cases
    )

    print("\n============================================")
    print("CASE CONSOLIDATION SUMMARY")
    print("============================================")

    print(
        f"Groups consolidated : "
        f"{consolidated_count}"
    )

    print(
        f"Cases archived      : "
        f"{archived_count}"
    )

    if consolidated_count == 0:

        print(
            "\n[✓] No duplicate investigations found."
        )

    else:

        print(
            "\n[✓] Related cases consolidated."
        )

    print(
        f"[✓] Case database saved: {CASES_FILE}"
    )


if __name__ == "__main__":
    consolidate_cases()
