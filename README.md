# Ephemeral | Email Header Analysis Tool

An analyst-grade, ephemeral email header and authentication analysis tool designed for learning, research, and security validation.

## Features
- **Deep Header Parsing**: Normalizes fields, extracts received chain, message IDs, and more.
- **Authentication Quality Analysis**: 
    - Real-time SPF/DMARC record lookups via Cloudflare DNS.
    - Evaluates policy strength (`-all` vs `~all`).
    - Detects DNS lookup limit violations.
    - Checks DKIM alignment and DMARC enforcement levels.
- **Anomaly Detection**: 
    - Hop-by-hop timestamp drift detection.
    - Private IP detection in transit.
    - Sender alignment checks (From vs Return-Path).
- **Infrastructure Reputation**:
    - Optional VirusTotal and AbuseIPDB integration.
    - Contextual risk labeling.
- **Modular Modes**: Standalone IP, Domain, and Attachment (metadata-only) analysis.
- **Privacy First**: 
    - 100% Client-side analysis.
    - No data persistence, no logs, no tracking.
    - Ephemeral execution in memory.

## Architecture
- **Frontend**: Static HTML5/JS hosted on GitHub Pages.
- **Backend**: Optional GitHub Actions workflow for batch/recorded analysis execution.
- **APIs**: VirusTotal, AbuseIPDB, Cloudflare DNS-over-HTTPS.

## Usage
1. Open `index.html`.
2. (Optional) Click **Configure APIs** to add your VirusTotal/AbuseIPDB keys. Keys are stored only in your browser's local storage.
3. Paste raw email headers into the **Full Analysis** tab.
4. Click **Start Analysis**.
5. Export results as Markdown or JSON for your report.

## Design Aesthetic
The UI follows a minimalist black & white theme, prioritizing legibility and analyst workflow efficiency.

---
*Built for security analysts. No data storage. No persistence.*
