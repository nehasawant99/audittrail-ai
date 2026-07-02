import json

# Define our cybersecurity knowledge matrix (deterministic rule mapping)
PORT_RISK_MATRIX = {
    21: {"severity": "High", "risk": "FTP Plaintext Authentication", "recommendation": "Disable FTP or migrate to SFTP (Port 22)."},
    23: {"severity": "Critical", "risk": "Telnet Plaintext Traffic", "recommendation": "Disable Telnet immediately. Use SSH (Port 22) instead."},
    25: {"severity": "Medium", "risk": "SMTP Relay Vulnerabilities", "recommendation": "Verify SMTP authentication and disable open relay."},
    53: {"severity": "Low", "risk": "DNS Zone Transfer Over TCP", "recommendation": "Ensure DNS zone transfers are restricted to authorized secondary servers."},
    80: {"severity": "Low", "risk": "Unencrypted HTTP Traffic", "recommendation": "Enforce HTTPS redirect using SSL/TLS certificates."},
    139: {"severity": "High", "risk": "NetBIOS Exploit Vector", "recommendation": "Disable NetBIOS over TCP/IP if not explicitly needed."},
    443: {"severity": "Informational", "risk": "Secure Web Traffic", "recommendation": "Maintain certificate hygiene and keep web servers patched."},
    445: {"severity": "Critical", "risk": "SMB Vulnerability (Potential EternalBlue)", "recommendation": "Restrict SMB traffic to internal assets and apply MS17-010 security updates."},
    3306: {"severity": "High", "risk": "Exposed MySQL Database Engine", "recommendation": "Bind MySQL database interface to localhost or restrict access via strict firewall rules."},
    3389: {"severity": "High", "risk": "Exposed Remote Desktop Protocol (RDP)", "recommendation": "Disable direct internet exposure. Restrict behind a VPN gateway with MFA."}
}

def analyze_scan_vulnerabilities(parsed_data):
    """
    Evaluates parsed Nmap structural objects against standard security policy vectors.
    Flags severity benchmarks and appends explicit advice profiles.
    """
    if "error" in parsed_data:
        return parsed_data

    analysis_report = {
        "target_ip": parsed_data["target_ip"],
        "scan_time": parsed_data["scan_time"],
        "os_details": parsed_data["os_details"],
        "overall_risk_score": 0, # Calculated dynamically
        "vulnerability_counts": {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0
        },
        "flagged_vulnerabilities": []
    }

    critical_weight = 10
    high_weight = 5
    medium_weight = 2
    low_weight = 1

    for port_info in parsed_data["ports"]:
        port_num = port_info["port"]
        service_name = port_info["service"]
        
        # Check if the scanned port matches a threat profile in our rules engine
        if port_num in PORT_RISK_MATRIX:
            rule = PORT_RISK_MATRIX[port_num]
            severity = rule["severity"]
            
            # Increment vulnerability risk tallies
            if severity in analysis_report["vulnerability_counts"]:
                analysis_report["vulnerability_counts"][severity] += 1
            
            # Update weighted score index
            if severity == "Critical": analysis_report["overall_risk_score"] += critical_weight
            elif severity == "High": analysis_report["overall_risk_score"] += high_weight
            elif severity == "Medium": analysis_report["overall_risk_score"] += medium_weight
            elif severity == "Low": analysis_report["overall_risk_score"] += low_weight

            # Append actionable findings block
            analysis_report["flagged_vulnerabilities"].append({
                "port": port_num,
                "protocol": port_info["protocol"],
                "service": service_name,
                "version": port_info["version"],
                "severity": severity,
                "threat": rule["risk"],
                "mitigation": rule["recommendation"]
            })
        else:
            # Fallback for untracked open ports
            if port_info["status"] == "open":
                analysis_report["flagged_vulnerabilities"].append({
                    "port": port_num,
                    "protocol": port_info["protocol"],
                    "service": service_name,
                    "version": port_info["version"],
                    "severity": "Low",
                    "threat": f"Unmonitored Active Service ({service_name})",
                    "mitigation": "Verify if this service layer needs to be exposed on the public boundary interface."
                })
                analysis_report["vulnerability_counts"]["Low"] += 1
                analysis_report["overall_risk_score"] += low_weight

    return analysis_report

# --- Core Validation Context ---
if __name__ == "__main__":
    # Mock validation block simulating parsed log engine input
    mock_parsed_input = {
        "target_ip": "192.168.33.12",
        "scan_time": "Tue Jun 30 12:29:05 2026",
        "os_details": "Ubuntu Linux 22.04",
        "ports": [
            {"port": 22, "protocol": "tcp", "status": "open", "service": "ssh", "version": "OpenSSH 8.9p1"},
            {"port": 80, "protocol": "tcp", "status": "open", "service": "http", "version": "Apache httpd 2.4.52"},
            {"port": 445, "protocol": "tcp", "status": "open", "service": "microsoft-ds", "version": "Samba 4.15"},
            {"port": 3306, "protocol": "tcp", "status": "open", "service": "mysql", "version": "MySQL 8.0.28"}
        ]
    }
    
    print("⚙️ Processing mock parsed log arrays through Rules Matrix...")
    report = analyze_scan_vulnerabilities(mock_parsed_input)
    print(json.dumps(report, indent=4))