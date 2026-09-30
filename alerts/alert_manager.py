import json
from status_manager import update_status

ALERT_FILE = "alerts.json"

def load_alerts():
    try:
        with open(ALERT_FILE, "r") as file:
            return json.load(file)

    except (FileNotFoundError, json.JSONDecodeError):
        return []


def show_alerts():

    alerts = load_alerts()

    if not alerts:
        print("\nNo alerts found.\n")
        return

    print("\n========== TRACEX ALERTS ==========\n")

    for alert in alerts:

        print(f"Alert ID      : {alert['alert_id']}")
        print(f"Rule          : {alert['detection_rule']}")
        print(f"Severity      : {alert['severity']}")
        print(f"Status        : {alert['status']}")
        print(f"Timestamp     : {alert['timestamp']}")
        print(f"Username      : {alert['username']}")
        print(f"Source IP     : {alert['source_ip']}")
        print(f"Service       : {alert['service']}")
        print(f"Attempts      : {alert['attempt_count']}")
        print(f"Time Window   : {alert['time_window']} seconds")
        print(f"Reason        : {alert['reason']}")
        print("-----------------------------------")

    print()


def main():

    while True:

        print("\n========== TRACEX ALERT MANAGER ==========")
        print("1. View Alerts")
        print("2. Update Alert Status")
        print("3. Exit")

        choice = input("\nSelect an option: ")

        if choice == "1":

            show_alerts()

        elif choice == "2":

            alert_id = input("Enter Alert ID: ")
            new_status = input(
                "Enter new status "
                "(NEW / ACKNOWLEDGED / INVESTIGATING / RESOLVED): "
            ).upper()

            update_status(alert_id, new_status)

        elif choice == "3":

            print("\nExiting TraceX Alert Manager.")
            break

        else:

            print("\nInvalid option. Please try again.")


if __name__ == "__main__":
    main()
