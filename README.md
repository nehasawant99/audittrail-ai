# AuditTrail AI

Developed exclusively for **The Hangover Part AI** Hackathon.

## Overview

AuditTrail AI is a lightweight, privacy-first Security Operations Center (SOC) log analysis application that processes raw security logs entirely on-device. It combines deterministic parsing, rule-based risk analysis, local knowledge graph storage, and SQLite-backed report tracking to provide fast, consistent, and API-free security analysis.

---

## System Architecture

```text
                 [ User Uploads File ]
                         │
                         ▼
        1. FAST REGEX PARSING (parser_engine.py)
     Extracts structured information such as IP addresses,
           operating systems, ports, and services.
                         │
                         ▼
      2. ZERO-COST SECURITY MATRIX (rules_engine.py)
      Classifies vulnerabilities, calculates risk scores,
          and generates mitigation recommendations.
             ┌───────────┴───────────┐
             ▼                       ▼
  3. COGNEE LOCAL STORAGE      4. SQLITE DATABASE
 Creates knowledge graph      Stores scan reports and
 nodes with metadata for      maintains dashboard history.
 contextual relationships.
             └───────────┬───────────┘
                         ▼
              5. INTERACTIVE SOC DASHBOARD
      Displays findings, risk summaries, and report history.
```

---

## Features

* Fast regex-based log parsing
* Rule-based security risk assessment
* Automatic vulnerability categorization
* Risk scoring with remediation suggestions
* Local Cognee knowledge graph integration
* SQLite report history and persistence
* Interactive SOC dashboard
* Fully offline processing (no external API dependency)

---

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/nehasawant/audittrail-ai.git
cd audittrail-ai
```

### 2. Create a Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Launch the Application

```bash
python app.py
```

Open your browser and visit:

```
http://127.0.0.1:5000
```

Upload a supported log file to view real-time parsing, security analysis, and interactive SOC reports.

---

## Technology Stack

* Python
* Flask
* SQLite
* Cognee
* HTML
* CSS
* JavaScript

---

## Project Workflow

1. Upload a raw security log.
2. Parse log entries into structured data.
3. Apply rule-based security analysis.
4. Generate risk scores and remediation guidance.
5. Store analysis in Cognee and SQLite.
6. Display findings through the SOC dashboard.

---

## Conclusion

AuditTrail AI provides a practical and privacy-focused approach to security log analysis. By combining deterministic parsing with rule-based detection and local data storage, the application performs the complete analysis pipeline without relying on external APIs or cloud services. This architecture minimizes latency, preserves sensitive log data, ensures consistent results, and offers security analysts an efficient offline solution for reviewing and managing security events.
