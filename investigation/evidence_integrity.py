import hashlib
import json
import os
from datetime import datetime


EVIDENCE_REGISTRY = "alerts/evidence_registry.json"

EVIDENCE_FILES = {
    "AUTH_LOG": "logs/auth.log",
    "ALERTS": "alerts/alerts.json",
    "CASES": "alerts/cases.json",
    "CORRELATION": "alerts/correlation_results.json",
}


def load_registry():
    if not os.path.exists(EVIDENCE_REGISTRY):
        return []

    try:
        with open(EVIDENCE_REGISTRY, "r") as f:
            data = json.load(f)

        return data if isinstance(data, list) else []

    except (json.JSONDecodeError, OSError):
        return []


def save_registry(registry):
    os.makedirs(
        os.path.dirname(EVIDENCE_REGISTRY),
        exist_ok=True
    )

    with open(EVIDENCE_REGISTRY, "w") as f:
        json.dump(registry, f, indent=4)


def timestamp():
    return datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def sha256_file(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(
            lambda: f.read(4096),
            b""
        ):
            sha256.update(chunk)

    return sha256.hexdigest()


def next_evidence_id(registry):

    highest = 0

    for item in registry:

        evidence_id = str(
            item.get("evidence_id", "")
        )

        if evidence_id.startswith("EVID-"):

            try:
                number = int(
                    evidence_id.split("-")[1]
                )

                highest = max(
                    highest,
                    number
                )

            except (ValueError, IndexError):
                pass

    return f"EVID-{highest + 1:04d}"


def register_evidence(
    registry,
    case_id,
    evidence_type,
    file_path
):

    if not os.path.exists(file_path):

        print(
            f"\n[!] Evidence file not found: "
            f"{file_path}"
        )

        return None

    file_hash = sha256_file(file_path)

    evidence = {

        "evidence_id":
            next_evidence_id(registry),

        "case_id":
            case_id,

        "evidence_type":
            evidence_type,

        "file_path":
            file_path,

        "sha256":
            file_hash,

        "registered_at":
            timestamp(),

        "last_verified_at":
            None,

        "integrity_status":
            "REGISTERED",

        "verification_history":
            []
    }

    registry.append(evidence)

    save_registry(registry)

    return evidence


def verify_evidence(evidence):

    file_path = evidence.get("file_path")
    original_hash = evidence.get("sha256")

    if not file_path:
        return "UNAVAILABLE", None

    if not os.path.exists(file_path):
        return "MISSING", None

    try:
        current_hash = sha256_file(file_path)

    except OSError:
        return "UNAVAILABLE", None

    verified_at = timestamp()

    if current_hash == original_hash:
        status = "INTACT"
    else:
        status = "CHANGED"

    evidence["last_verified_at"] = verified_at
    evidence["integrity_status"] = status

    evidence.setdefault(
        "verification_history",
        []
    ).append({

        "verified_at":
            verified_at,

        "original_sha256":
            original_hash,

        "current_sha256":
            current_hash,

        "status":
            status
    })

    return status, current_hash


def display_registry(registry):

    print()
    print("=" * 80)
    print("              TRACEX EVIDENCE REGISTRY")
    print("=" * 80)

    if not registry:

        print()
        print("[i] No evidence registered yet.")
        return

    for evidence in registry:

        print()

        print(
            f"Evidence ID     : "
            f"{evidence.get('evidence_id')}"
        )

        print(
            f"Case ID         : "
            f"{evidence.get('case_id')}"
        )

        print(
            f"Type            : "
            f"{evidence.get('evidence_type')}"
        )

        print(
            f"File            : "
            f"{evidence.get('file_path')}"
        )

        print(
            f"SHA-256         : "
            f"{evidence.get('sha256')}"
        )

        print(
            f"Registered At   : "
            f"{evidence.get('registered_at')}"
        )

        print(
            f"Last Verified   : "
            f"{evidence.get('last_verified_at')}"
        )

        print(
            f"Integrity       : "
            f"{evidence.get('integrity_status')}"
        )

        print("-" * 80)


def register_menu(registry):

    print()
    print("=" * 80)
    print("              REGISTER EVIDENCE")
    print("=" * 80)

    print()

    items = list(EVIDENCE_FILES.items())

    for index, (name, path) in enumerate(
        items,
        start=1
    ):

        print(
            f"{index}. {name:<15} {path}"
        )

    print()

    try:

        choice = int(
            input(
                "Select evidence: "
            ).strip()
        )

    except ValueError:

        print("[!] Invalid selection.")
        return

    if choice < 1 or choice > len(items):

        print("[!] Invalid selection.")
        return

    evidence_type, file_path = items[
        choice - 1
    ]

    case_id = input(
        "Enter Case ID: "
    ).strip()

    if not case_id:

        print("[!] Case ID is required.")
        return

    evidence = register_evidence(
        registry,
        case_id,
        evidence_type,
        file_path
    )

    if evidence:

        print()
        print("[✓] Evidence registered.")

        print(
            f"Evidence ID : "
            f"{evidence['evidence_id']}"
        )

        print(
            f"SHA-256     : "
            f"{evidence['sha256']}"
        )

        print(
            "Integrity   : REGISTERED"
        )


def verification_menu(registry):

    if not registry:

        print()
        print("[i] No evidence is registered.")
        return

    display_registry(registry)

    evidence_id = input(
        "\nEnter Evidence ID to verify: "
    ).strip()

    evidence = next(
        (
            item
            for item in registry
            if item.get("evidence_id")
            == evidence_id
        ),
        None
    )

    if not evidence:

        print()
        print("[!] Evidence ID not found.")
        return

    status, current_hash = verify_evidence(
        evidence
    )

    save_registry(registry)

    print()
    print("=" * 80)
    print("              INTEGRITY VERIFICATION")
    print("=" * 80)

    print(
        f"\nEvidence ID     : "
        f"{evidence.get('evidence_id')}"
    )

    print(
        f"File            : "
        f"{evidence.get('file_path')}"
    )

    print(
        f"Original SHA256 : "
        f"{evidence.get('sha256')}"
    )

    print(
        f"Current SHA256  : "
        f"{current_hash}"
    )

    print()

    if status == "INTACT":

        print("[✓] INTACT")
        print(
            "Evidence content matches "
            "the registered SHA-256 hash."
        )

    elif status == "CHANGED":

        print("[!] CHANGED")
        print(
            "Evidence content no longer "
            "matches the registered hash."
        )

    elif status == "MISSING":

        print("[!] MISSING")
        print(
            "The registered evidence file "
            "could not be found."
        )

    else:

        print("[!] UNAVAILABLE")

    print("=" * 80)


def main():

    registry = load_registry()

    while True:

        print()
        print("=" * 80)
        print("       TRACEX EVIDENCE INTEGRITY ENGINE")
        print("=" * 80)

        print()
        print("1. Register Evidence")
        print("2. Verify Evidence Integrity")
        print("3. View Evidence Registry")
        print("4. Verify All Evidence")
        print("0. Exit")

        print()

        choice = input(
            "Select option: "
        ).strip()

        if choice == "1":

            register_menu(registry)

        elif choice == "2":

            verification_menu(registry)

        elif choice == "3":

            display_registry(registry)

        elif choice == "4":

            if not registry:

                print()
                print(
                    "[i] No evidence registered."
                )

                continue

            print()
            print(
                "========== VERIFYING ALL EVIDENCE =========="
            )

            for evidence in registry:

                status, current_hash = (
                    verify_evidence(evidence)
                )

                print(
                    f"{evidence.get('evidence_id')} | "
                    f"{evidence.get('evidence_type')} | "
                    f"{status}"
                )

            save_registry(registry)

            print()
            print(
                "[✓] Verification completed."
            )

        elif choice == "0":

            print()
            print(
                "Exiting TraceX Evidence Integrity Engine."
            )

            break

        else:

            print()
            print("[!] Invalid option.")


if __name__ == "__main__":
    main()
