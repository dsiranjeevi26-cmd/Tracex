import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

CORRELATION_FILE = (
    BASE_DIR
    / "alerts"
    / "correlation_results.json"
)


def load_correlations():
    """Load correlation groups from correlation_results.json."""

    try:
        with open(CORRELATION_FILE, "r") as file:
            data = json.load(file)

            if isinstance(data, list):
                return data

            if isinstance(data, dict):
                return [data]

    except (
        FileNotFoundError,
        json.JSONDecodeError
    ):
        pass

    return []


def save_correlations(correlations):
    """Save updated correlation groups."""

    with open(CORRELATION_FILE, "w") as file:
        json.dump(
            correlations,
            file,
            indent=4
        )


def calculate_risk(correlation):
    """Calculate evidence-based risk score."""

    counts = correlation.get(
        "event_counts",
        {}
    )

    failed = counts.get(
        "failed_logins",
        0
    )

    successful = counts.get(
        "successful_logins",
        0
    )

    sudo = counts.get(
        "sudo_events",
        0
    )

    account_changes = counts.get(
        "account_changes",
        0
    )

    score = 0
    factors = []

    if failed >= 5:

        score += 30

        factors.append(
            f"{failed} failed authentication "
            "attempts detected"
        )

    if successful >= 1:

        score += 20

        factors.append(
            "Successful login observed after "
            "failed authentication activity"
        )

    if sudo >= 1:

        score += 20

        factors.append(
            "Privileged command activity observed"
        )

    if account_changes >= 1:

        score += 20

        factors.append(
            "Account modification activity observed"
        )

    score = min(
        score,
        100
    )

    if score >= 80:

        level = "HIGH"

    elif score >= 50:

        level = "MEDIUM"

    else:

        level = "LOW"

    return {
        "score": score,
        "level": level,
        "factors": factors
    }


def main():

    print()
    print("=" * 60)
    print("             TRACEX RISK ENGINE")
    print("=" * 60)

    correlations = load_correlations()

    if not correlations:

        print()
        print(
            "[i] No correlation results available."
        )

        print(
            "[i] Run the correlation engine first."
        )

        return

    print()
    print(
        f"[+] Correlation groups loaded: "
        f"{len(correlations)}"
    )

    for index, correlation in enumerate(
        correlations,
        start=1
    ):

        result = calculate_risk(
            correlation
        )

        correlation["risk_score"] = (
            result["score"]
        )

        correlation["risk_level"] = (
            result["level"]
        )

        correlation["risk_factors"] = (
            result["factors"]
        )

        print()
        print("-" * 60)

        print(
            f"CORRELATION GROUP #{index}"
        )

        print("-" * 60)

        print(
            f"Username       : "
            f"{correlation.get('username')}"
        )

        print(
            f"Source IP      : "
            f"{correlation.get('source_ip')}"
        )

        print(
            f"Service        : "
            f"{correlation.get('service')}"
        )

        print()

        print(
            f"Risk Score     : "
            f"{result['score']}/100"
        )

        print(
            f"Risk Level     : "
            f"{result['level']}"
        )

        print()
        print("Risk Factors:")

        if result["factors"]:

            for factor in result["factors"]:

                print(
                    f"  • {factor}"
                )

        else:

            print(
                "  • No significant risk "
                "factors identified"
            )

        print()

        print(
            "Assessment: This is an evidence-based "
            "risk score for investigation "
            "prioritization, not proof of "
            "malicious activity."
        )

    save_correlations(
        correlations
    )

    print()
    print(
        "[+] Risk results saved to:"
    )

    print(
        f"    {CORRELATION_FILE}"
    )

    print()
    print("=" * 60)
    print("[✓] Risk analysis completed.")
    print("=" * 60)


if __name__ == "__main__":
    main()
