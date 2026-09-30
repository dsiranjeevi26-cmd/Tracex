import subprocess
import sys
from pathlib import Path
from datetime import datetime
import json


# ============================================================
# TRACEX MASTER AUTOMATED PIPELINE
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

CASES_FILE = BASE_DIR / "alerts" / "cases.json"


# ============================================================
# LOAD CASES
# ============================================================

def load_cases():

    try:

        if not CASES_FILE.exists():
            return []

        with open(
            CASES_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

        if isinstance(data, list):
            return data

        if isinstance(data, dict):
            return [data]

        return []

    except Exception as error:

        print(
            f"[!] Unable to load cases: {error}"
        )

        return []


# ============================================================
# SELECT REPORT CASE
# ============================================================

def select_report_case():

    cases = load_cases()

    if not cases:
        return None

    def risk_score(case):

        try:
            return int(
                case.get(
                    "risk_score",
                    0
                )
            )

        except Exception:
            return 0

    cases = sorted(
        cases,
        key=risk_score,
        reverse=True
    )

    return cases[0].get(
        "case_id"
    )


# ============================================================
# BANNER
# ============================================================

def banner():

    print()
    print("=" * 72)
    print("                    TRACEX SOC PIPELINE")
    print("=" * 72)
    print()
    print("        Detect • Trace • Investigate • Report")
    print()
    print("=" * 72)


# ============================================================
# RUN AUTOMATED STAGE
# ============================================================

def run_stage(
    number,
    title,
    module,
    input_text=None
):

    print()
    print("=" * 72)
    print(
        f" STEP {number}: {title}"
    )
    print("=" * 72)
    print()

    try:

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                module
            ],
            cwd=BASE_DIR,
            input=input_text,
            text=True
        )

        if result.returncode != 0:

            print()
            print(
                f"[!] FAILED: {title}"
            )

            print(
                f"[!] Module: {module}"
            )

            return False

        print()
        print(
            f"[+] COMPLETED: {title}"
        )

        return True

    except Exception as error:

        print()
        print(
            f"[!] ERROR: {error}"
        )

        return False


# ============================================================
# MAIN
# ============================================================

def main():

    banner()

    start_time = datetime.now()

    print(
        f"Started: "
        f"{start_time.strftime('%Y-%m-%d %H:%M:%S')}"
    )

    print(
        f"Project: {BASE_DIR}"
    )

    # --------------------------------------------------------
    # AUTOMATED CORE PIPELINE
    # --------------------------------------------------------

    stages = [

        (
            1,
            "Detection Hub",
            "detection.detection_engine"
        ),

        (
            2,
            "Correlation Engine",
            "correlation.correlator"
        ),

        (
            3,
            "Risk Engine",
            "risk.risk_engine"
        ),

        (
            4,
            "Case Synchronization",
            "investigation.auto_case"
        ),

        (
            5,
            "Case Consolidation",
            "investigation.case_consolidator"
        ),

        (
            6,
            "MITRE ATT&CK Mapping",
            "investigation.mitre_mapper"
        ),

        (
            7,
            "Resolution Assessment",
            "investigation.resolution_engine"
        )

    ]

    completed = 0

    # --------------------------------------------------------
    # RUN CORE STAGES
    # --------------------------------------------------------

    for number, title, module in stages:

        success = run_stage(
            number,
            title,
            module
        )

        if not success:

            print()
            print("=" * 72)
            print("                 PIPELINE STOPPED")
            print("=" * 72)

            print(
                f"Failed stage : {number}"
            )

            print(
                f"Stage        : {title}"
            )

            print(
                f"Module       : {module}"
            )

            return 1

        completed += 1

    # --------------------------------------------------------
    # AUTOMATIC REPORT GENERATION
    # --------------------------------------------------------

    report_case = select_report_case()

    if report_case:

        print()
        print("=" * 72)
        print(" STEP 8: Incident Report Generation")
        print("=" * 72)
        print()

        print(
            f"[+] Automatically selected case: "
            f"{report_case}"
        )

        print(
            "[+] Case selection is based on highest "
            "stored risk score."
        )

        print()

        success = run_stage(
            8,
            "Incident Report Generation",
            "reports.report_generator",
            input_text=f"{report_case}\n"
        )

        if not success:

            print()
            print(
                "[!] Report generation failed."
            )

            return 1

        completed += 1

    else:

        print()
        print(
            "[!] No cases available for report generation."
        )

        return 1

    # --------------------------------------------------------
    # COMPLETION
    # --------------------------------------------------------

    end_time = datetime.now()

    duration = (
        end_time - start_time
    ).total_seconds()

    print()
    print("=" * 72)
    print("                 TRACEX PIPELINE COMPLETE")
    print("=" * 72)

    print()

    print(
        f"Stages completed : "
        f"{completed}/8"
    )

    print(
        f"Duration         : "
        f"{duration:.2f} seconds"
    )

    print()

    print(
        "LOG"
        " → DETECTION"
        " → ALERT"
        " → CORRELATION"
        " → RISK"
        " → CASE"
        " → CONSOLIDATION"
        " → MITRE"
        " → RESOLUTION"
        " → REPORT"
    )

    print()

    print(
        "[+] Automated investigation pipeline completed."
    )

    print()
    print(
        "[+] Analyst-controlled modules remain available:"
    )

    print(
        "    • Response Engine"
    )

    print(
        "    • Evidence Integrity Engine"
    )

    print(
        "    • IOC / Threat Intelligence Engine"
    )

    print()
    print(
        "[+] Open the Streamlit dashboard for SOC analysis."
    )

    print("=" * 72)

    return 0


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    sys.exit(
        main()
    )
