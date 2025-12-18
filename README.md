# Ephemeral | Email Forensic Analyzer

A client-side, privacy-first forensic analysis tool for email headers, infrastructure, and reputation. Designed for SOC analysts and security researchers to rapidly triage suspicious emails without sending data to a third-party server.

## 🚀 Key Features

### 1. Advanced Header Analysis
- **Authentication Validation:** Real-time checks for SPF, DKIM, and DMARC alignment and policy strength.
- **Hop-by-Hop Tracing:** Visualizes the email's path, flagging delays and identifying the true Origin IP.
- **Anomaly Detection:** Highlights "impossible" travel (timestamp drift), private IPs in public chains, and spoofing attempts.

### 2. Forensic Identity & Infrastructure
- **Deep IP Analysis:** 
    - **6-Point Identity:** ISP, ASN, Geolocation, Usage Type (Residential vs Data Center/VPN), and Hostname.
    - **Risk Scoring:** Automated "Traffic Light" system (🔴 Red / 🟡 Yellow / 🟢 Green) based on abuse scores and usage patterns.
- **Domain Intelligence:** 
    - **"Birth Certificate" Checks:** Calculates Domain Age (New < 7 days = 🔴), checks Registrar, and detects Typosquatting (e.g., `micr0soft.com`).
    - **DNS Hygiene:** Validates MX, NS, AAAA records and SSL status.

### 3. Integrated Threat Intelligence
- **API Integration:** Connects directly to **VirusTotal** and **AbuseIPDB** from your browser (using your own keys) to fetch reputation data.
- **Automated Enrichment:** Every IP and Domain found in the headers is automatically analyzed in the background.

### 4. Robust Fallback System ("Manual Check")
- **No API Key? No Problem.** The tool operates in "Unverified" mode if keys are missing or CORS blocks the request.
- **Active Assist:** Automatically generates "One-Click Verification" links for every entity:
    - **IPs:** Direct links to AbuseIPDB, Talos, Shodan, and Spamhaus.
    - **Domains:** Direct links to MXToolbox, Talos, and UrlScan.

### 5. Modular Tools
- **Standalone IP Console:** Analyze lists of IPs with the same depth as the full report.
- **Standalone Domain Console:** Perform deep reconnaissance on domains.
- **Attachment Analysis:** Calculate file hashes (SHA-256) locally and check them against VirusTotal.

## 🔒 Privacy & Architecture
- **100% Client-Side:** All parsing and logic happen in your browser's JavaScript engine.
- **Ephemeral State:** No database, no local storage persistence (except API keys if saved), and no external logging.
- **Direct-to-Source:** API calls go directly from your browser to the vendor (VirusTotal/AbuseIPDB); we never see your data.

## 🛠️ Usage
1. Open `index.html` in any modern browser.
2. **(Optional)** Click **⚙️ Config** to add your VirusTotal / AbuseIPDB keys.
3. Paste raw email headers into the **Header Analysis** tab.
4. View the report:
    - **Section 1:** Email Summary & Spoofing Checks.
    - **Section 2:** Security Intelligence (Forensic table of all IPs).
    - **Section 3:** Domain Health (Age, Reputation, Infrastructure).
5. Use the **Standalone** tabs for ad-hoc investigations.

## 📝 Exports
- Generate **Markdown** reports for ticketing systems (Jira/ServiceNow).
- Export raw **JSON** data for evidence logs.

---
*Built for Analysts, by Analysts.*
