# AuditTrail AI 

Developed exclusively for **The Hangover Part AI** Hackathon.

An ultra-fast, local-first Security Operations Center (SOC) dashboard that parses raw, unstructured network scans into an actionable vulnerability timeline and local knowledge graph.

---

##  The Core Problem & Our Twist

Most traditional AI-driven security log analyzers suffer from high cloud latency, unpredictable runtime costs, and "Context Amnesia"—frequently misinterpreting or completely dropping open network properties across scanning sessions. 

###  Built WITHOUT External Cloud AI APIs
To solve this reliably for enterprise security workflows, **AuditTrail AI purposefully does not use external cloud-based LLM or generative AI endpoints.** Instead, we achieved high-fidelity security analysis and structured data tracking using a 100% free, deterministic, and blazing-fast local architecture.

---

##  The Local-First Architecture

The application handles incoming logs cleanly through a completely non-blocking asynchronous pipeline:

1. **Fast Deterministic Extraction (`parser_engine.py`):** Uses optimized Regular Expressions (Regex) to instantly strip target hosts, operating systems, and active port numbers out of raw text files.
2. **Hardcoded Threat Matrix (`rules_engine.py`):** Passes the extracted configuration arrays through a static, zero-cost cybersecurity vulnerability matrix. It scores threats automatically (Critical, High, Medium, Low) and attaches exact mitigation steps without hallucination risks.
3. **Cognee Local Memory Network:** Integrates **Cognee's native data framework structural layer**. Extracted metadata packages are wrapped directly into `DataItem` entities and offloaded to a dedicated background event loop using `asyncio.run_coroutine_threadsafe()`. This satisfies structural graph requirements completely locally.
4. **Relational Persistence Layer:** Simultaneously commits report snapshots into a local SQLite repository to power a lightning-fast, dark-mode monitoring interface.

---

##  Tech Stack

* **Core Language:** Python 3.14
* **Web Framework:** Flask (Multi-threaded backend)
* **Data & Graph Engine:** Cognee (Local Structural Memory Layer)
* **Database:** SQLite3
* **Asynchronous Control:** Threading & Asyncio (Non-blocking worker pool configuration)

---

##  The End-to-End Workflow

```text
                 [ User Uploads File ] 
                         │
                         ▼
         1. FAST REGEX PARSING (parser_engine.py) 
     Strips raw text into clear variables (IP, OS, ports)
                         │
                         ▼
       2. ZERO-COST SECURITY MATRIX (rules_engine.py)
      Maps risk categories, scores danger, adds fixes
                         │
             ┌───────────┴───────────┐
             ▼                       ▼
    3. COGNEE LOCAL STORAGE    4. SQLITE DASHBOARD
     Creates data graph node    Saves report state for
    with metadata attributes   the history timeline UI
             │                       │
             └───────────┬───────────┘
                         ▼
            [ 5. Interactive SOC Screen ]


  ## Quick Start & Installation

1. Clone & Set Up Environment

'''Bash 
        git clone [https://github.com/nehasawant/audittrail-ai.git](https://github.com/nehasawant/audittrail-ai.git)
        cd audittrail-ai
        python3 -m venv .venv
        source .venv/bin/activate
        pip install -r requirements.txt

2. Launch the SOC Dashboard

''' Bash
         python app.py

Open your browser and navigate to http://127.0.0.1:5000 to upload raw log files and observe live processing!


###   Conclusion

AuditTrail AI demonstrates a reliable, practical approach to log analysis. By utilizing deterministic parsing alongside local structural tracking through Cognee, the system handles data pipeline requirements entirely on-device. This setup provides security analysts with a private tool that operates with minimal overhead, eliminates API latency, and ensures data consistency without relying on external endpoints.