import json
import os


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_FILE = os.path.join(BASE_DIR, "mitre", "mitre_rules.json")


def load_mitre_rules():
    with open(RULES_FILE, "r") as file:
        return json.load(file)


def map_correlated_evidence(
    failed_logins,
    successful_login,
    sudo_events,
    account_changes,
    ssh_activity=True
):
    rules = load_mitre_rules()

    mappings = []

    # Brute Force
    if failed_logins > 0:
        rule = rules["BRUTE_FORCE_AUTH"]

        mappings.append({
            "evidence": f"{failed_logins} failed login attempts",
            "technique_id": rule["technique_id"],
            "technique_name": rule["technique_name"]
        })

    # SSH
    if ssh_activity:
        rule = rules["SSH_LOGIN"]

        mappings.append({
            "evidence": "SSH authentication activity",
            "technique_id": rule["technique_id"],
            "technique_name": rule["technique_name"]
        })

    # Sudo
    if sudo_events > 0:
        rule = rules["SUDO_ACTIVITY"]

        mappings.append({
            "evidence": f"{sudo_events} sudo event(s)",
            "technique_id": rule["technique_id"],
            "technique_name": rule["technique_name"]
        })

    # Account Modification
    if account_changes > 0:
        rule = rules["ACCOUNT_MODIFICATION"]

        mappings.append({
            "evidence": f"{account_changes} account modification event(s)",
            "technique_id": rule["technique_id"],
            "technique_name": rule["technique_name"]
        })

    return mappings


def display_mitre_mapping(mappings):

    print("\n========== TRACEX MITRE ATT&CK MAPPING ==========\n")

    if not mappings:
        print("No MITRE ATT&CK techniques mapped.")
        return

    for mapping in mappings:

        print(f"Evidence      : {mapping['evidence']}")
        print(f"Technique ID  : {mapping['technique_id']}")
        print(f"Technique     : {mapping['technique_name']}")
        print("---------------------------------------------")


if __name__ == "__main__":

    mappings = map_correlated_evidence(
        failed_logins=6,
        successful_login=1,
        sudo_events=1,
        account_changes=1,
        ssh_activity=True
    )

    display_mitre_mapping(mappings)
