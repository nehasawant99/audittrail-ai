import re
import json
import os

def parse_nmap_log(file_path):
    """
    Parses a standard raw Nmap scan text file using regex.
    Extracts Target IP, Scan Status, Operating System, and Open Ports matrix.
    """
    if not os.path.exists(file_path):
        return {"error": f"File not found at {file_path}"}

    with open(file_path, "r", encoding="utf-8") as file:
        log_content = file.read()

    # 1. Initialize data schema
    parsed_data = {
        "target_ip": "Unknown",
        "scan_time": "Unknown",
        "os_details": "Not Detected",
        "metrics": {
            "total_open_ports": 0
        },
        "ports": []
    }

    # 2. Extract Target IP (Matches 'Nmap scan report for 192.168.1.1' or similar)
    ip_match = re.search(r"Nmap scan report for ([\d\.]+)", log_content)
    if ip_match:
        parsed_data["target_ip"] = ip_match.group(1)

    # 3. Extract OS Detection if available
    os_match = re.search(r"OS details:\s+(.+)", log_content)
    if os_match:
        parsed_data["os_details"] = os_match.group(1).strip()

    # 4. Extract Scan Execution Time
    time_match = re.search(r"Nmap done at ([^;\n]+)", log_content)
    if time_match:
        parsed_data["scan_time"] = time_match.group(1).strip()

    # 5. Extract Ports, Protocols, Status, and Services
    # Matches lines like: "80/tcp   open  http    Apache httpd 2.4.41"
    # Capture groups: (Port)/(Protocol)  (Status)  (Service)  (Optional Version)
    port_pattern = re.compile(
        r"(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+([\w\-]+)(?:\s+(.+))?"
    )

    for line in log_content.splitlines():
        match = port_pattern.match(line.strip())
        if match:
            port_num = match.group(1)
            protocol = match.group(2)
            status = match.group(3)
            service = match.group(4)
            version = match.group(5).strip() if match.group(5) else "Unknown"

            if status == "open":
                parsed_data["metrics"]["total_open_ports"] += 1

            parsed_data["ports"].append({
                "port": int(port_num),
                "protocol": protocol,
                "status": status,
                "service": service,
                "version": version
            })

    return parsed_data

# --- Quick Test Loop ---
if __name__ == "__main__":
    # Create sample log directory and file if it doesn't exist yet for validation
    os.makedirs("sample_logs", exist_ok=True)
    test_file = "sample_logs/nmap_scan.txt"
    
    if not os.path.exists(test_file):
        print(f"⚠️ Place your raw Nmap log into '{test_file}' to test.")
    else:
        print(f"⚙️ Deterministically parsing target log: {test_file}...")
        result = parse_nmap_log(test_file)
        print(json.dumps(result, indent=4))