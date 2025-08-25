**📧 Ephemeral Email Header & Attachment Analysis Tool**

A **full-stack security analysis platform** to analyze email headers, URLs, IPs, domains, and file attachments in real-time.

It integrates with VirusTotal, AbuseIPDB, WHOIS, and YARA rules to detect suspicious or malicious indicators.

The project comes with:

🔹 **Backend** (FastAPI) for analysis & integrations

🔹 **Frontend** (React + Tailwind) for a clean dashboard UI

🔹 **Docker Compose** for easy deployment

All results are **ephemeral** – stored only in-memory (default TTL: 15 minutes).

**✨ Features**

**🔍 Email Header Analysis**

Extracts public IPs, domains, and mail authentication results (SPF, DKIM, DMARC).

Detects routing anomalies & suspicious metadata.

**🌐 URL & Domain Analysis**

URL normalization & parsing.

WHOIS lookup, DNS resolution (A/MX).

Reputation checks with VirusTotal.

**📡 IP Analysis**

AbuseIPDB confidence scoring.

VirusTotal IP reputation.

Detects public vs private IPs.

**📎 File Attachment Analysis**

File type detection via python-magic.

YARA scanning for malware families.

Hashing (MD5/SHA1/SHA256).

VirusTotal hash lookup & live scan submission.

Entropy analysis for obfuscation.

**📺 Dashboard & Logs**

Modern React dashboard with tables/cards.

WebSocket live logs while analysis runs.

Results auto-expire after TTL.

**🛠️ Tech Stack**

Backend: FastAPI, cachetools, yara-python, python-whois, dnspython, python-magic

Frontend: React, Tailwind, ShadCN UI, WebSockets

Integrations: VirusTotal API, AbuseIPDB API

Deployment: Docker, Docker Compose

**🚀 Getting Started**

**1️⃣ Clone the repository**

git clone https://github.com/your-org/ephemeral-email-analyzer.git

cd ephemeral-email-analyzer

**2️⃣ Environment setup**
Copy .env.example → .env and set API keys:

VIRUSTOTAL_API_KEY=your_key

ABUSEIPDB_API_KEY=your_key

**3️⃣ Run with Docker Compose**

docker-compose up --build

Frontend → http://localhost:3000

Backend → http://localhost:8000

**4️⃣ API Endpoints (Backend)**

GET /health → Service health

POST /analyze/header → Analyze email headers

POST /analyze/url → Analyze suspicious URLs

POST /analyze/attachment → Analyze uploaded files

GET /results/{analysis_id} → Get analysis results

DELETE /results/{analysis_id} → Clear results

WS /ws/{analysis_id} → Real-time log stream

**📊 Example Workflow**

Upload email headers → /analyze/header

System extracts IOCs → runs WHOIS, DNS, VirusTotal, AbuseIPDB checks

Upload suspicious file → /analyze/attachment

Watch real-time logs → ws://localhost:8000/ws/{analysis_id}

Fetch results → /results/{analysis_id}


**⚠️ Notes & Limitations**

Ephemeral Storage → All results expire after 15 minutes.

Rate Limits → VirusTotal/AbuseIPDB APIs may throttle requests.

File Size → VT file uploads >32MB not supported.

Security → Never hardcode API keys in code.

**📄 License**

MIT License – free to use, modify, and distribute.

**🤝 Contributing**

Pull requests & feature suggestions welcome!

Planned improvements:

Redis cache backend for scale

Sandbox integration (Cuckoo/Hybrid Analysis)

Extended YARA rules library

