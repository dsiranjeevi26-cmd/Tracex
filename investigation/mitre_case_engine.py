import json
import os


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CASES_FILE = os.path.join(
    BASE_DIR,
    "alerts",
    "cases.json"
)

CORRELATION_FILE = os.path.join(
    BASE_DIR,
    "alerts",
    "correlation_results.json"
)


MITRE_MAP = {
    "failed_logins": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "description": "Repeated authentication failures were observed."
    },

    "successful_logins": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "description": "A successful authentication followed the observed failures."
    },

    "sudo_events": {
        "technique_id": "T1548.003",
        "technique_name": "Sudo and Sudo Caching",
        "description": "Privileged sudo activity was observed."
    },

    "account_changes": {
        "technique_id": "T1098",
        "technique_name": "Account Manipulation",
        "description": "An account modification event was observed."
    }
}


def load_json(path, default):
    try:
        with open(path, "r") as file:
            return json.load(file)

    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_json(path, data):
    with open(path, "w") as file:
        json.dump(data, file, indent=4)


def normalize(data, key=None):

    if isinstance(data, list):
        return data

    if isinstance(data, dict):

        if key and isinstance(data.get(key), list):
            return data[key]

        return [data]

    return []


def select_case(cases):

    if not cases:
        print("\n[!] No cases available.")
        return None

    print("\n" + "=" * 65)
    print("                    AVAILABLE CASES")
    print("=" * 65)

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


def build_mitre_evidence(correlation):

    event_counts = correlation.get(
        "event_counts",
        {}
    )

    mappings = []

    for evidence_type, mitre_data in MITRE_MAP.items():

        count = event_counts.get(
            evidence_type,
            0
        )

        if count > 0:

            mappings.append(
                {
                    "evidence_type": evidence_type,
                    "event_count": count,
                    "technique_id":
                        mitre_data["technique_id"],
                    "technique_name":
                        mitre_data["technique_name"],
                    "description":
                        mitre_data["description"]
                }
            )

    return mappings


def display_mitre(mappings):

    print("\n" + "=" * 65)
    print("             MITRE ATT&CK CASE EVIDENCE")
    print("=" * 65)

    if not mappings:

        print("\nNo MITRE mappings supported by current evidence.")
        return

    for mapping in mappings:

        print("\n" + "-" * 65)

        print(
            f"Technique ID   : "
            f"{mapping['technique_id']}"
        )

        print(
            f"Technique      : "
            f"{mapping['technique_name']}"
        )

        print(
            f"Evidence       : "
            f"{mapping['evidence_type']}"
        )

        print(
            f"Event Count    : "
            f"{mapping['event_count']}"
        )

        print(
            f"Context        : "
            f"{mapping['description']}"
        )

    print("\n" + "-" * 65)

    print(
        "Note: MITRE mappings provide investigative context."
    )

    print(
        "They do not independently confirm malicious activity."
    )


def save_mitre_to_case(case, mappings, cases):

    case["mitre_evidence"] = mappings

    save_json(
        CASES_FILE,
        cases
    )

    print("\n[+] MITRE evidence linked to case.")
    print("[+] Saved to alerts/cases.json")


def main():

    print("\n" + "=" * 65)
    print("        TRACEX MITRE-TO-CASE EVIDENCE ENGINE")
    print("=" * 65)

    cases = normalize(
        load_json(
            CASES_FILE,
            []
        ),
        "cases"
    )

    correlations = normalize(
        load_json(
            CORRELATION_FILE,
            []
        ),
        "correlations"
    )

    print(
        f"\nCases loaded       : {len(cases)}"
    )

    print(
        f"Correlation groups : {len(correlations)}"
    )

    case = select_case(cases)

    if not case:
        return

    correlation = find_correlation(
        case,
        correlations
    )

    if not correlation:

        print(
            "\n[!] Matching correlation evidence not found."
        )

        return

    mappings = build_mitre_evidence(
        correlation
    )

    display_mitre(mappings)

    if mappings:

        save_mitre_to_case(
            case,
            mappings,
            cases
        )


if __name__ == "__main__":
    main()
