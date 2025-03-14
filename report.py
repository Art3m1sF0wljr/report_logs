import os
import re
from datetime import datetime
from collections import defaultdict

def extract_timestamp(filename):
    match = re.match(r"(\d{8}_\d{6})_security\.log", filename)
    if match:
        return datetime.strptime(match.group(1), "%Y%m%d_%H%M%S")
    return None

def process_logs(log_folder):
    log_files = [f for f in os.listdir(log_folder) if f.endswith(".log") and f != "report.log"]
    
    current_log = None
    if "current_security.log" in log_files:
        current_log = "current_security.log"
        log_files.remove(current_log)

    log_files.sort(key=lambda x: extract_timestamp(x) if extract_timestamp(x) else datetime.min)

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
    unknown_attack_file = "report/UNKNOWN_ATTACKS_report.txt"

    os.makedirs("report", exist_ok=True)

    attack_data = {attack: defaultdict(set) for attack in attack_types}
    unknown_attacks = defaultdict(set)
    unique_ips = set()  # Store all unique IPs

    with open(report_file, "r") as report:
        for line in report:
            match = re.search(r'kernel: (.*? ATTACK)', line)
            if match:
                attack_name = match.group(1)
                src_match = re.search(r'SRC=([\d\.]+)', line)
                dpt_match = re.search(r'DPT=(\d+)', line)
                src_ip = src_match.group(1) if src_match else "Unknown"
                dpt = int(dpt_match.group(1)) if dpt_match else None
                
                if attack_name in attack_types:
                    attack_file_path = attack_types[attack_name]
                else:
                    attack_file_path = unknown_attack_file
                    unknown_attacks[src_ip].add(dpt)

                with open(attack_file_path, "a") as attack_file:
                    attack_file.write(line)
                
                if attack_name in attack_types:
                    attack_data[attack_name][src_ip].add(dpt)
                unique_ips.add(src_ip)  # Collect unique IPs

    for attack_name, ip_data in attack_data.items():
        attack_file_path = attack_types[attack_name]
        with open(attack_file_path, "a") as attack_file:
            attack_file.write("\n\n\n")
            for ip in sorted(ip_data.keys()):
                sorted_ports = sorted(ip_data[ip])
                port_list = ", ".join(map(str, sorted_ports))
                attack_file.write(f"{ip}: {port_list}\n")

    # Write unknown attacks to file
    with open(unknown_attack_file, "a") as unknown_file:
        unknown_file.write("\n\n\n")
        for ip in sorted(unknown_attacks.keys()):
            sorted_ports = sorted(filter(None, unknown_attacks[ip]))
            port_list = ", ".join(map(str, sorted_ports)) if sorted_ports else "Unknown ports"
            unknown_file.write(f"{ip}: {port_list}\n")

    # Write all unique IPs to ip.txt
    with open("ip.txt", "w") as ip_file:
        for ip in sorted(unique_ips):
            ip_file.write(f"{ip}\n")

if __name__ == "__main__":
    log_folder = "/home/pi/program/security_log/"
    process_logs(log_folder)
    print("Attack reports generated. Check individual attack report files.")
    print("List of unique IPs saved in ip.txt.")
