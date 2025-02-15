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

if __name__ == "__main__":
    log_folder = "./logs"  # Change this to your actual log folder path
    process_logs(log_folder)
    print("Report generated: report.log")
