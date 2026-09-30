import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

CASES_FILE = (
    BASE_DIR
    / "alerts"
    / "cases.json"
)


MITRE_MAPPING = {

    "failed_logins": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "description": (
            "Repeated failed authentication "
            "attempts were observed."
        )
    },

    "successful_logins": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "description": (
            "A successful authentication event "
            "was observed after authentication "
            "failure activity."
        )
    },

    "sudo_events": {
        "technique_id": "T1548.003",
        "technique_name": "Sudo and Sudo Caching",
        "description": (
            "Privileged activity using sudo "
            "was observed."
        )
    },

    "account_changes": {
        "technique_id": "T1098",
        "technique_name": "Account Manipulation",
        "description": (
            "An account modification event "
            "was observed."
        )
    }
}


def load_cases():

    try:

        with open(CASES_FILE, "r") as file:

            data = json.load(file)

            if isinstance(data, list):
                return data

    except (
        FileNotFoundError,
        json.JSONDecodeError
    ):

        pass

    return []


def save_cases(cases):

    CASES_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(CASES_FILE, "w") as file:

        json.dump(
            cases,
            file,
            indent=4,
            default=str
        )


def create_mappings(case):

    counts = case.get(
        "event_counts",
        {}
    )

    mappings = []

    for evidence_type, mapping in MITRE_MAPPING.items():

        count = counts.get(
            evidence_type,
            0
        )

        if count <= 0:
            continue

        mappings.append({

            "technique_id":
                mapping["technique_id"],

            "technique_name":
                mapping["technique_name"],

            "evidence_type":
                evidence_type,

            "evidence_count":
                count,

            "description":
                mapping["description"],

            "assessment":
                (
                    "Technique is relevant to "
                    "the observed evidence and "
                    "requires analyst validation."
                )
        })

    return mappings


def display_case_mapping(case):

    mappings = case.get(
        "mitre_mappings",
        []
    )

    print()
    print("=" * 60)

    print(
        f"        MITRE ATT&CK CASE MAPPING"
    )

    print("=" * 60)

    print()

    print(
        f"Case ID        : "
        f"{case.get('case_id')}"
    )

    print(
        f"Username       : "
        f"{case.get('username')}"
    )

    print(
        f"Source IP      : "
        f"{case.get('source_ip')}"
    )

    print(
        f"Risk Level     : "
        f"{case.get('risk_level')}"
    )

    print()

    print("---------- MITRE TECHNIQUES ----------")

    if not mappings:

        print(
            "  No ATT&CK techniques mapped."
        )

    else:

        for mapping in mappings:

            print()

            print(
                f"  {mapping['technique_id']} "
                f"- {mapping['technique_name']}"
            )

            print(
                f"    Evidence : "
                f"{mapping['evidence_type']}"
            )

            print(
                f"    Count    : "
                f"{mapping['evidence_count']}"
            )

            print(
                f"    Context  : "
                f"{mapping['description']}"
            )

    print()

    print(
        "Assessment: ATT&CK mappings provide "
        "investigative context and do not by "
        "themselves confirm malicious activity."
    )

    print()

    print("=" * 60)


def main():

    print()
    print("=" * 60)
    print("       TRACEX MITRE ATT&CK MAPPER")
    print("=" * 60)

    cases = load_cases()

    if not cases:

        print()
        print(
            "[i] No investigation cases found."
        )

        print(
            "[i] Create a case before running "
            "MITRE mapping."
        )

        return

    mapped_cases = 0
    total_mappings = 0

    for case in cases:

        mappings = create_mappings(
            case
        )

        case["mitre_mappings"] = mappings

        if mappings:

            mapped_cases += 1

            total_mappings += len(
                mappings
            )

        display_case_mapping(
            case
        )

    save_cases(cases)

    print()
    print("=" * 60)

    print(
        f"[+] Cases processed   : "
        f"{len(cases)}"
    )

    print(
        f"[+] Cases with MITRE  : "
        f"{mapped_cases}"
    )

    print(
        f"[+] Total mappings    : "
        f"{total_mappings}"
    )

    print(
        f"[✓] Cases updated     : "
        f"{CASES_FILE}"
    )

    print("=" * 60)


if __name__ == "__main__":

    main()
