import os
import re
from datetime import datetime

def extract_timestamp(filename):
    # Assuming the filename format is YYYYMMDD_HHMMSS_security.log, e.g. "20250212_114259_security.log"
    match = re.match(r"(\d{8}_\d{6})_security\.log", filename)
    if match:
        return datetime.strptime(match.group(1), "%Y%m%d_%H%M%S")
    return None

def process_logs(log_folder):
    # Get a list of all the security log files
    log_files = [f for f in os.listdir(log_folder) if f.endswith(".log") and f != "report.log"]
    
    # Separate "current_security.log" from other logs
    current_log = None
    if "current_security.log" in log_files:
        current_log = "current_security.log"
        log_files.remove(current_log)
    
    # Sort the other log files by timestamp extracted from the filenames
    log_files.sort(key=lambda x: extract_timestamp(x) if extract_timestamp(x) else datetime.min)

    # Add "current_security.log" to the end of the list
    if current_log:
        log_files.append(current_log)

    report_file = os.path.join(log_folder, "report.log")
    
    with open(report_file, "w") as report:
        for filename in log_files:
            file_path = os.path.join(log_folder, filename)
            with open(file_path, "r") as log_file:
                for line in log_file:
                    if not line.startswith("[account]"):
                        report.write(line)

    # Now, parse the report.log and categorize attacks
    categorize_attacks(report_file)

def categorize_attacks(report_file):
    attack_types = {
        "UDP_FLOODING ATTACK": "report/UDP_FLOODING_report.txt",
        "TCP_FLOODING ATTACK": "report/TCP_FLOODING_report.txt",
        "LAND ATTACK": "report/LAND_report.txt",
        "UDP PORT SCAN ATTACK": "report/UDP_PORT_SCAN_report.txt",
	"TCP PORT SCAN ATTACK": "report/TCP_PORT_SCAN_report.txt",
	"SYN_FLOODING ATTACK": "report/SYN_FLOODING_report.txt",
	"ICMP REDIRECT ATTACK": "report/ICMP_REDIRECT_report.txt",
    }

    # Create all attack report files if they don't exist
    for attack_type in attack_types.values():
        with open(attack_type, "w") as _:
            pass  # Just create the empty files

    # Create the unknown attacks file
    with open("report/unknown_attacks.txt", "w") as unknown_file:
        pass  # Just create the empty file
    
    # Read the report.log and filter attacks
    with open(report_file, "r") as report:
        for line in report:
            # Look for attack types
            match = re.search(r'kernel: (.*? ATTACK)', line)
            if match:
                attack_name = match.group(1)
                if attack_name in attack_types:
                    # Write known attack to corresponding file
                    attack_file_path = os.path.join(attack_types[attack_name])
                    with open(attack_file_path, "a") as attack_file:
                        attack_file.write(line)
                else:
                    # Write unknown attack to unknown_attacks.txt
                    with open("unknown_attacks.txt", "a") as unknown_file:
                        unknown_file.write(line)

if __name__ == "__main__":
    log_folder = "/security_log/"  # Change this to your actual log folder path
    process_logs(log_folder)
    print("Attack reports generated. Check individual attack report files.")
