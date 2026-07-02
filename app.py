import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash
from parser_engine import parse_nmap_log
from rules_engine import analyze_scan_vulnerabilities

app = Flask(__name__)
app.secret_key = "audit_trail_secret_key_for_hackathon"
UPLOAD_FOLDER = "sample_logs"
DATABASE = "database/audit_logs.db"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs("database", exist_ok=True)

def get_db_connection():
    """Establishes a connection to the local SQLite storage engine."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Creates schema tables to preserve historical metrics without external database costs."""
    conn = get_db_connection()
    cursor = conn.cursor()
    # Table for storing master report data
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_ip TEXT,
            scan_time TEXT,
            os_details TEXT,
            overall_risk_score INTEGER,
            critical_count INTEGER,
            high_count INTEGER,
            medium_count INTEGER,
            low_count INTEGER
        )
    """)
    # Table for storing individual granular port vulnerabilities
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER,
            port INTEGER,
            protocol TEXT,
            service TEXT,
            version TEXT,
            severity TEXT,
            threat TEXT,
            mitigation TEXT,
            FOREIGN KEY (report_id) REFERENCES scan_reports (id)
        )
    """)
    conn.commit()
    conn.close()

@app.route("/")
def index():
    """Renders the main Security Operations Center (SOC) dashboard tracking historical scans."""
    conn = get_db_connection()
    reports = conn.execute("SELECT * FROM scan_reports ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("index.html", reports=reports)

@app.route("/upload", methods=["POST"])
def upload_file():
    """Handles log file ingestion, processes parsing + rule execution, and writes to DB."""
    if "log_file" not in request.files:
        flash("No file part picked.")
        return redirect(url_for("index"))
    
    file = request.files["log_file"]
    if file.filename == "":
        flash("No file selected for parsing.")
        return redirect(url_for("index"))

    if file:
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
        file.save(file_path)

        # 1. Run the deterministic analytical pipeline
        parsed_raw_data = parse_nmap_log(file_path)
        final_threat_report = analyze_scan_vulnerabilities(parsed_raw_data)

        if "error" in final_threat_report:
            flash(f"Error processing logs: {final_threat_report['error']}")
            return redirect(url_for("index"))

        # 2. Database transaction mapping
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO scan_reports (target_ip, scan_time, os_details, overall_risk_score, critical_count, high_count, medium_count, low_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            final_threat_report["target_ip"],
            final_threat_report["scan_time"],
            final_threat_report["os_details"],
            final_threat_report["overall_risk_score"],
            final_threat_report["vulnerability_counts"]["Critical"],
            final_threat_report["vulnerability_counts"]["High"],
            final_threat_report["vulnerability_counts"]["Medium"],
            final_threat_report["vulnerability_counts"]["Low"]
        ))
        
        report_id = cursor.lastrowid

        # Insert discovered port records
        for vuln in final_threat_report["flagged_vulnerabilities"]:
            cursor.execute("""
                INSERT INTO vulnerabilities (report_id, port, protocol, service, version, severity, threat, mitigation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report_id, vuln["port"], vuln["protocol"], vuln["service"], 
                vuln["version"], vuln["severity"], vuln["threat"], vuln["mitigation"]
            ))

        conn.commit()
        conn.close()
        
        flash("Audit log ingested and verified successfully!")
        return redirect(url_for("view_report", report_id=report_id))

@app.route("/report/<int:report_id>")
def view_report(report_id):
    """Fetches details for a single target node scan to feed the drilldown UI view."""
    conn = get_db_connection()
    report = conn.execute("SELECT * FROM scan_reports WHERE id = ?", (report_id,)).fetchone()
    vulnerabilities = conn.execute("SELECT * FROM vulnerabilities WHERE report_id = ?", (report_id,)).fetchall()
    conn.close()
    
    if report is None:
        return "Report Asset Matrix Not Found", 404
        
    return render_template("scan_results.html", report=report, vulnerabilities=vulnerabilities)

if __name__ == "__main__":
    init_db() # Run SQL database initialization check
    print("🚀 SOC Audit Trail Dashboard active on http://127.0.0.1:5000")
    app.run(debug=True)