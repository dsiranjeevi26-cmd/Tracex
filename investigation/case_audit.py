import json
import os
from datetime import datetime


CASES_FILE = "alerts/cases.json"


def load_cases():
    if not os.path.exists(CASES_FILE):
        print("[!] cases.json not found.")
        return []

    try:
        with open(CASES_FILE, "r") as f:
            data = json.load(f)

        return data if isinstance(data, list) else []

    except json.JSONDecodeError:
        print("[!] Invalid cases.json.")
        return []


def show_cases(cases):
    print("\n========== TRACEX CASE AUDIT ==========\n")

    for case in cases:
        print(
            f"{case.get('case_id')} | "
            f"{case.get('username')} | "
            f"{case.get('source_ip')} | "
            f"Status: {case.get('status')} | "
            f"Risk: {case.get('risk_score', 0)}/100 "
            f"{case.get('risk_level', 'UNKNOWN')}"
        )


def select_case(cases):
    case_id = input("\nEnter Case ID: ").strip()

    for case in cases:
        if case.get("case_id") == case_id:
            return case

    print("[!] Case not found.")
    return None


def parse_timestamp(value):
    if not value:
        return datetime.max

    value = str(value).strip()

    formats = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S.%f"
    ]

    for fmt in formats:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue

    return datetime.max


def add_event(events, timestamp, event_type, description):
    events.append(
        {
            "timestamp": timestamp,
            "type": event_type,
            "description": description
        }
    )


def build_audit(case):
    events = []

    # --------------------------------------------------
    # CASE CREATION
    # --------------------------------------------------
    if case.get("created_at"):
        add_event(
            events,
            case["created_at"],
            "CASE_CREATED",
            f"Case {case.get('case_id')} created."
        )

    # --------------------------------------------------
    # STATUS HISTORY
    # --------------------------------------------------
    for item in case.get("status_history", []):
        add_event(
            events,
            item.get("timestamp", ""),
            "STATUS_CHANGE",
            f"{item.get('from', 'UNKNOWN')} → "
            f"{item.get('to', 'UNKNOWN')} "
            f"({item.get('reason', 'No reason provided')})"
        )

    # --------------------------------------------------
    # DECISION HISTORY
    # --------------------------------------------------
    for item in case.get("decision_history", []):
        add_event(
            events,
            item.get("timestamp", ""),
            "ANALYST_DECISION",
            f"Decision: {item.get('decision', 'UNKNOWN')}"
        )

    # --------------------------------------------------
    # ANALYST NOTES
    # --------------------------------------------------
    for item in case.get("analyst_notes", []):
        add_event(
            events,
            item.get("timestamp", ""),
            "ANALYST_NOTE",
            item.get("note", "")
        )

    # --------------------------------------------------
    # INVESTIGATION ACTIVITIES
    # --------------------------------------------------
    for item in case.get("investigation_activity", []):
        add_event(
            events,
            item.get("timestamp", ""),
            "INVESTIGATION_ACTIVITY",
            item.get("activity", "")
        )

    # --------------------------------------------------
    # CASE REOPEN HISTORY
    # --------------------------------------------------
    for item in case.get("reopen_history", []):
        add_event(
            events,
            item.get("timestamp", ""),
            "CASE_REOPENED",
            f"Case reopened: {item.get('reason', '')}"
        )

    # --------------------------------------------------
    # CASE RESOLUTION
    # --------------------------------------------------
    resolution = case.get("resolution")

    if resolution:
        add_event(
            events,
            resolution.get("timestamp", ""),
            "CASE_RESOLVED",
            f"Resolution: {resolution.get('reason', '')}"
        )

    # --------------------------------------------------
    # PROPER DATETIME SORTING
    # --------------------------------------------------
    events.sort(
        key=lambda event: parse_timestamp(event.get("timestamp"))
    )

    return events


def display_audit(case):
    events = build_audit(case)

    print("\n========== CASE AUDIT TRAIL ==========\n")

    print(f"Case ID   : {case.get('case_id')}")
    print(f"User      : {case.get('username')}")
    print(f"Source IP : {case.get('source_ip')}")
    print(f"Status    : {case.get('status')}")
    print(
        f"Risk      : {case.get('risk_score', 0)}/100 "
        f"{case.get('risk_level', 'UNKNOWN')}"
    )

    print("\n----------------------------------------")
    print("CHRONOLOGICAL ACTIVITY")
    print("----------------------------------------")

    if not events:
        print("[!] No audit events found.")
        return

    for index, event in enumerate(events, start=1):
        print(f"\n[{index}] {event['timestamp']}")
        print(f"    Type : {event['type']}")
        print(f"    Info : {event['description']}")

    print("\n----------------------------------------")
    print(f"Total audit events: {len(events)}")
    print("----------------------------------------")


def main():
    cases = load_cases()

    if not cases:
        print("[!] No cases available.")
        return

    show_cases(cases)

    case = select_case(cases)

    if not case:
        return

    display_audit(case)


if __name__ == "__main__":
    main()
