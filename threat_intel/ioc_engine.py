import json
import os
import re
from datetime import datetime


IOC_REGISTRY = "alerts/ioc_registry.json"
AUTH_LOG = "logs/auth.log"


def timestamp():
    return datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def load_registry():

    if not os.path.exists(IOC_REGISTRY):
        return []

    try:

        with open(IOC_REGISTRY, "r") as f:
            data = json.load(f)

        return data if isinstance(data, list) else []

    except (json.JSONDecodeError, OSError):

        return []


def save_registry(registry):

    os.makedirs(
        "alerts",
        exist_ok=True
    )

    with open(IOC_REGISTRY, "w") as f:

        json.dump(
            registry,
            f,
            indent=4
        )


def next_ioc_id(registry):

    highest = 0

    for item in registry:

        ioc_id = str(
            item.get("ioc_id", "")
        )

        if ioc_id.startswith("IOC-"):

            try:

                number = int(
                    ioc_id.split("-")[1]
                )

                highest = max(
                    highest,
                    number
                )

            except (ValueError, IndexError):

                pass

    return f"IOC-{highest + 1:04d}"


def extract_ip_addresses():

    if not os.path.exists(AUTH_LOG):

        print(
            f"[!] Log file not found: {AUTH_LOG}"
        )

        return []

    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    found_ips = []

    with open(
        AUTH_LOG,
        "r"
    ) as f:

        for line in f:

            matches = re.findall(
                ip_pattern,
                line
            )

            for ip in matches:

                if ip not in found_ips:

                    found_ips.append(ip)

    return found_ips


def extract_iocs(
    registry,
    case_id
):

    ips = extract_ip_addresses()

    if not ips:

        print()
        print(
            "[i] No IP indicators found."
        )

        return

    created = 0

    for ip in ips:

        already_exists = any(

            item.get("value") == ip
            and item.get("case_id") == case_id

            for item in registry
        )

        if already_exists:

            print(
                f"[i] IOC already exists: {ip}"
            )

            continue

        ioc = {

            "ioc_id":
                next_ioc_id(registry),

            "case_id":
                case_id,

            "ioc_type":
                "IP",

            "value":
                ip,

            "source":
                "auth.log",

            "classification":
                "PUBLIC_IP_REQUIRES_REVIEW",

            "threat_intelligence_status":
                "NOT_LOOKED_UP",

            "analyst_status":
                "REQUIRES_REVIEW",

            "created_at":
                timestamp(),

            "analyst_note":
                ""
        }

        registry.append(ioc)

        created += 1

        print()
        print(
            f"[✓] IOC created: "
            f"{ioc['ioc_id']}"
        )

        print(
            f"    Type           : "
            f"{ioc['ioc_type']}"
        )

        print(
            f"    Value          : "
            f"{ioc['value']}"
        )

        print(
            f"    Classification : "
            f"{ioc['classification']}"
        )

    save_registry(registry)

    print()

    if created:

        print(
            f"[✓] {created} IOC(s) "
            f"added to registry."
        )

    else:

        print(
            "[i] No new IOCs added."
        )


def display_registry(registry):

    print()
    print("=" * 75)
    print(
        "             TRACEX IOC REGISTRY"
    )
    print("=" * 75)

    if not registry:

        print()
        print(
            "[i] IOC registry is empty."
        )

        return

    for ioc in registry:

        print()

        print(
            f"IOC ID          : "
            f"{ioc.get('ioc_id')}"
        )

        print(
            f"Case ID         : "
            f"{ioc.get('case_id')}"
        )

        print(
            f"Type            : "
            f"{ioc.get('ioc_type')}"
        )

        print(
            f"Value           : "
            f"{ioc.get('value')}"
        )

        print(
            f"Source          : "
            f"{ioc.get('source')}"
        )

        print(
            f"Classification  : "
            f"{ioc.get('classification')}"
        )

        print(
            f"TI Status       : "
            f"{ioc.get('threat_intelligence_status')}"
        )

        print(
            f"Analyst Status  : "
            f"{ioc.get('analyst_status')}"
        )

        print(
            f"Created At      : "
            f"{ioc.get('created_at')}"
        )

        print("-" * 75)


def update_ioc_status(registry):

    if not registry:

        print()
        print(
            "[i] No IOCs available."
        )

        return

    display_registry(registry)

    ioc_id = input(
        "\nEnter IOC ID: "
    ).strip()

    ioc = next(
        (
            item
            for item in registry
            if item.get("ioc_id") == ioc_id
        ),
        None
    )

    if not ioc:

        print(
            "[!] IOC not found."
        )

        return

    print()
    print("Analyst Status:")
    print("1. REQUIRES_REVIEW")
    print("2. RELEVANT")
    print("3. BENIGN")
    print("4. SUSPICIOUS")

    choice = input(
        "\nSelect status: "
    ).strip()

    status_map = {

        "1": "REQUIRES_REVIEW",
        "2": "RELEVANT",
        "3": "BENIGN",
        "4": "SUSPICIOUS"
    }

    if choice not in status_map:

        print(
            "[!] Invalid status."
        )

        return

    ioc["analyst_status"] = status_map[
        choice
    ]

    note = input(
        "Analyst note: "
    ).strip()

    ioc["analyst_note"] = note

    ioc["last_updated_at"] = timestamp()

    save_registry(registry)

    print()
    print(
        "[✓] IOC status updated."
    )


def main():

    registry = load_registry()

    while True:

        print()
        print("=" * 75)
        print(
            "        TRACEX IOC & THREAT INTELLIGENCE ENGINE"
        )
        print("=" * 75)

        print()
        print("1. Extract IOCs from auth.log")
        print("2. View IOC Registry")
        print("3. Update IOC Analyst Status")
        print("0. Exit")

        print()

        choice = input(
            "Select option: "
        ).strip()

        if choice == "1":

            case_id = input(
                "Enter Case ID: "
            ).strip()

            if not case_id:

                print(
                    "[!] Case ID is required."
                )

                continue

            extract_iocs(
                registry,
                case_id
            )

        elif choice == "2":

            display_registry(
                registry
            )

        elif choice == "3":

            update_ioc_status(
                registry
            )

        elif choice == "0":

            print()
            print(
                "Exiting TraceX IOC Engine."
            )

            break

        else:

            print(
                "[!] Invalid option."
            )


if __name__ == "__main__":
    main()
