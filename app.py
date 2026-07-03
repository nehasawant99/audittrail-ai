import threading
import os
import sqlite3
import asyncio
import cognee  # <--- Import Cognee natively
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

# --- Secure Background Loop Setup for Cognee ---
_loop = asyncio.new_event_loop()

def start_background_loop(loop):
    asyncio.set_event_loop(loop)
    loop.run_forever()

# Spin up a permanent background thread to host Cognee's data operations
threading.Thread(target=start_background_loop, args=(_loop,), daemon=True).start()

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
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

# --- Async Cognee Ingestion Wrapper ---
async def save_to_cognee_memory(ip, os_info, ports_list):
    """Feeds extracted log profiles directly into Cognee's local structural graph layer."""
    from cognee.tasks.ingestion.data_item import DataItem
    
    ports_string = ", ".join([f"Port {p['port']}({p['service']})" for p in ports_list])
    memory_payload = f"Host node {ip} running {os_info} has active open services: {ports_string}."
    
    # Pack as a structural DataItem node for native graph architecture mapping
    memory_node = DataItem(
        data=memory_payload,
        label="Cybersecurity_Audit_Trail",
        external_metadata={
            "target_ip": ip,
            "os_details": os_info
        }
    )
    
    print(f"[Cognee Local] Committing structural memory node for IP: {ip}")
    await cognee.remember(memory_node)

@app.route("/")
def index():
    conn = get_db_connection()
    reports = conn.execute("SELECT * FROM scan_reports ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("index.html", reports=reports)

@app.route("/upload", methods=["POST"])
def upload_file():
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

        # 1. Run the deterministic data extraction logic
        parsed_raw_data = parse_nmap_log(file_path)
        final_threat_report = analyze_scan_vulnerabilities(parsed_raw_data)

        if "error" in final_threat_report:
            flash(f"Error processing logs: {final_threat_report['error']}")
            return redirect(url_for("index"))

        # 2. TRIGGER COGNEE BACKGROUND LIFECYCLE 
        # By removing .result(), we let it process in the background without freezing the webpage!
        try:
            asyncio.run_coroutine_threadsafe(
                save_to_cognee_memory(
                    final_threat_report["target_ip"],
                    final_threat_report["os_details"],
                    parsed_raw_data["ports"]
                ),
                _loop
            )
            print("[Cognee Lifecycle] Dispatched to background thread pipeline.")
        except Exception as async_err:
            print(f"[Cognee Thread Exception] Ignored to protect UI flow: {async_err}")

        # 3. Database relational saving (runs immediately)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_reports (target_ip, scan_time, os_details, overall_risk_score, critical_count, high_count, medium_count, low_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            final_threat_report["target_ip"], final_threat_report.get("scan_time", "Unknown"), final_threat_report["os_details"],
            final_threat_report["overall_risk_score"], final_threat_report["vulnerability_counts"]["Critical"],
            final_threat_report["vulnerability_counts"]["High"], final_threat_report["vulnerability_counts"]["Medium"],
            final_threat_report["vulnerability_counts"]["Low"]
        ))
        
        report_id = cursor.lastrowid

        for vuln in final_threat_report["flagged_vulnerabilities"]:
            cursor.execute("""
                INSERT INTO vulnerabilities (report_id, port, protocol, service, version, severity, threat, mitigation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report_id, vuln["port"], vuln["protocol"], vuln["service"], 
                vuln["version"], vuln["severity"], vuln["threat"], vuln["mitigation"]
            ))

        conn.commit()
        conn.close()
        
        flash("Audit log ingested and committed to Cognee Memory Network successfully!")
        return redirect(url_for("view_report", report_id=report_id))
    
@app.route("/report/<int:report_id>")
def view_report(report_id):
    conn = get_db_connection()
    report = conn.execute("SELECT * FROM scan_reports WHERE id = ?", (report_id,)).fetchone()
    vulnerabilities = conn.execute("SELECT * FROM vulnerabilities WHERE report_id = ?", (report_id,)).fetchall()
    conn.close()
    
    if report is None:
        return "Report Asset Matrix Not Found", 404
        
    return render_template("scan_results.html", report=report, vulnerabilities=vulnerabilities)

if __name__ == "__main__":
    init_db()
    print("🚀 SOC Audit Dashboard with Cognee Memory active on http://127.0.0.1:5000")
    # Note: debug=True can sometimes spin up a second tracker process; 
    # if it double-triggers, you can set debug=False for perfect demo stability.
    app.run(debug=True)