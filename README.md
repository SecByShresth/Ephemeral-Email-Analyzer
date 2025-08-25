# 📧 Ephemeral Email Header & Attachment Analysis Tool (Backend)

A **FastAPI-based backend service** for analyzing email headers, URLs, IPs, domains, and file attachments in real-time.  
It integrates with **VirusTotal**, **AbuseIPDB**, **WHOIS**, and **YARA rules** to detect suspicious or malicious indicators.  

This service is designed to be ephemeral, using an **in-memory TTL cache** (default: 15 minutes) to store analysis results temporarily.  

---

## ✨ Features

- **Email Header Analysis**  
  - Extracts public IPs, domains, and mail authentication results (SPF, DKIM, DMARC).  
  - Identifies routing anomalies and suspicious metadata.  

- **URL & Domain Analysis**  
  - URL normalization and parsing.  
  - WHOIS lookup, DNS resolution (A/MX records).  
  - Reputation checks with VirusTotal.  

- **IP Analysis**  
  - Checks AbuseIPDB for abuse confidence and reports.  
  - VirusTotal IP reputation analysis.  
  - Private vs public IP detection.  

- **File Attachment Analysis**  
  - MIME type detection with `python-magic`.  
  - YARA rules scanning for common malware families.  
  - Hashing (MD5, SHA1, SHA256).  
  - VirusTotal file hash lookup & live scan submission.  
  - Entropy analysis for obfuscation/packing detection.  

- **Real-Time Logging**  
  - WebSocket endpoint streams logs to connected clients.  
  - Analysis steps and warnings pushed live.  

- **Ephemeral Storage**  
  - Analysis results cached for 15 minutes (configurable).  
  - Data automatically cleared after TTL expiration.  

---

## 🛠️ Tech Stack

- [FastAPI](https://fastapi.tiangolo.com/) – Web framework  
- [cachetools](https://pypi.org/project/cachetools/) – TTL-based caching  
- [yara-python](https://github.com/VirusTotal/yara-python) – Malware pattern matching  
- [python-whois](https://pypi.org/project/python-whois/) – WHOIS lookups  
- [dnspython](https://www.dnspython.org/) – DNS resolution  
- [python-magic](https://github.com/ahupp/python-magic) – File type detection  
- [VirusTotal API](https://developers.virustotal.com/) – Threat intelligence  
- [AbuseIPDB API](https://docs.abuseipdb.com/) – IP reputation  

---

## 🚀 Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/your-org/email-analysis-backend.git
cd email-analysis-backend

2. Install dependencies
bash
Copy
Edit
pip install -r requirements.txt

3. Configure API keys
Set the following environment variables in your shell or .env file:

bash
Copy
Edit
export VIRUSTOTAL_API_KEY="your_virustotal_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_key"
export HYBRID_ANALYSIS_API_KEY="your_hybrid_analysis_key"
(Hardcoded keys in code should be replaced with env variables for production use.)

4. Run the server
bash
Copy
Edit
uvicorn main:app --reload --host 0.0.0.0 --port 8000
📡 API Endpoints
Health Check
bash
Copy
Edit
GET /health
Returns API health, cache status, and configured API keys.

Email Header Analysis
pgsql
Copy
Edit
POST /analyze/header
Body:

json
Copy
Edit
{
  "headers": "raw email header text here"
}
URL Analysis
bash
Copy
Edit
POST /analyze/url
Body:

json
Copy
Edit
{
  "urls": ["http://suspicious.example", "malware.site"]
}
File Attachment Analysis
bash
Copy
Edit
POST /analyze/attachment
Multipart Form-Data: file upload

Get Analysis Results
bash
Copy
Edit
GET /results/{analysis_id}
Clear Results
bash
Copy
Edit
DELETE /results/{analysis_id}
WebSocket Logs
bash
Copy
Edit
ws://localhost:8000/ws/{analysis_id}
Receives real-time log messages for ongoing analysis.

📊 Example Workflow
Upload email headers → /analyze/header

System extracts IPs & domains → runs AbuseIPDB, VirusTotal, WHOIS, DNS checks

Upload suspicious attachments → /analyze/attachment

Subscribe to logs → ws://.../ws/{analysis_id}

Fetch final summary → /results/{analysis_id}

⚠️ Notes & Limitations
Ephemeral Storage: All results are cached in memory and expire after 15 minutes.

Rate Limits: External APIs (VirusTotal, AbuseIPDB) may throttle requests.

File Size Limits: VirusTotal uploads >32MB are not supported.

Security: Do not hardcode API keys in production.

📄 License
MIT License – Free to use, modify, and distribute.

🤝 Contributing
Pull requests and feature suggestions are welcome!
Future improvements may include:

Redis-backed cache for scalability.

Support for sandbox analysis (Cuckoo/Hybrid Analysis).

Extended YARA rules library.