// App logic
const reputation = new ReputationProvider();
const analyzer = new Analyzer(reputation);
let currentReport = null;

document.addEventListener('DOMContentLoaded', () => {
    // Config Panel
    const configBtn = document.getElementById('config-btn');
    const configPanel = document.getElementById('config-panel');
    const vtInput = document.getElementById('vt-key-input');
    const abuseInput = document.getElementById('abuse-key-input');

    vtInput.value = reputation.vtKey;
    abuseInput.value = reputation.abuseKey;

    configBtn.addEventListener('click', () => {
        configPanel.classList.toggle('hidden');
    });

    document.getElementById('save-keys-btn').addEventListener('click', () => {
        reputation.setKeys(vtInput.value, abuseInput.value);
        configPanel.classList.add('hidden');
        alert('API keys loaded for this session. They will be discarded on refresh.');
    });

    // Tab switching
    const tabs = document.querySelectorAll('.mode-tab');
    const sections = document.querySelectorAll('.input-section');

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            sections.forEach(s => s.classList.remove('active'));

            tab.classList.add('active');
            const mode = tab.dataset.mode;
            document.getElementById(`${mode}-section`).classList.add('active');

            // Hide results when switching back to input
            document.getElementById('results-container').style.display = 'none';
        });
    });

    // Toggle comparison mode
    document.getElementById('compare-mode').addEventListener('change', (e) => {
        document.getElementById('compare-input-wrapper').classList.toggle('hidden', !e.target.checked);
    });

    // Analyze Full
    document.getElementById('analyze-btn').addEventListener('click', async () => {
        const raw = document.getElementById('header-input').value;
        if (!raw) return alert('Please paste email headers first.');

        const compareRaw = document.getElementById('compare-header-input').value;
        const compareHeaders = compareRaw ? EmailParser.parseHeaders(compareRaw) : null;

        showLoading('Parsing Headers & Analyzing Authentication...');
        const headers = EmailParser.parseHeaders(raw);

        // Stage 1: Static
        try {
            currentReport = await analyzer.analyzeStatic(headers, compareHeaders);
            updateLoading('Querying Reputation APIs (VT/AbuseIPDB)...');
            displayReport(currentReport, true); // Partial display

            // Stage 2: Enrichment
            currentReport = await analyzer.enrichReport(currentReport);
            updateLoading('Analysis Complete.');
            displayReport(currentReport, false); // Final display
        } catch (e) {
            console.error(e);
            alert('Analysis failed: ' + e.message);
            document.getElementById('results-container').style.display = 'none';
        }
    });

    // Analyze Attach
    document.getElementById('attach-upload').addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        document.getElementById('analyze-attach-btn').disabled = false;
        document.getElementById('analyze-attach-btn').onclick = async () => {
            showLoading();
            const result = await analyzeFile(file);
            displayStandaloneResults('Attachment Analysis', [result]);
        };
    });

    // Analyze IP
    document.getElementById('analyze-ip-btn').addEventListener('click', async () => {
        const ips = document.getElementById('ip-input').value.split(/[\n,]/).filter(x => x.trim());
        if (ips.length === 0) return alert('Please enter at least one IP.');

        showLoading();
        const results = await analyzer.analyzeIPs(ips);
        displayStandaloneResults('IP Analysis', results);
    });

    // Analyze Domain
    document.getElementById('analyze-domain-btn').addEventListener('click', async () => {
        const domains = document.getElementById('domain-input').value.split(/[\n,]/).filter(x => x.trim());
        if (domains.length === 0) return alert('Please enter at least one domain.');

        showLoading();
        const results = await analyzer.analyzeDomains(domains);
        displayStandaloneResults('Domain Analysis', results);
    });

    // File Upload Handler
    document.getElementById('file-upload').addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (event) => {
            document.getElementById('header-input').value = event.target.result;
        };
        reader.readAsText(file);
    });

    // Export Buttons
    document.getElementById('export-md').addEventListener('click', () => {
        if (!currentReport) return;
        const md = Exporter.toMarkdown(currentReport);
        Exporter.download(md, `analysis-report-${Date.now()}.md`, 'text/markdown');
    });

    document.getElementById('export-json').addEventListener('click', () => {
        if (!currentReport) return;
        const json = Exporter.toJSON(currentReport);
        Exporter.download(json, `analysis-report-${Date.now()}.json`, 'application/json');
    });

    document.getElementById('clear-btn').addEventListener('click', () => {
        if (confirm('Are you sure you want to clear all data? This will also wipe your API keys for this session.')) {
            document.getElementById('header-input').value = '';
            document.getElementById('ip-input').value = '';
            document.getElementById('domain-input').value = '';
            document.getElementById('results-container').style.display = 'none';
            reputation.setKeys('', '');
            vtInput.value = '';
            abuseInput.value = '';
            currentReport = null;
        }
    });
});

async function analyzeFile(file) {
    const buffer = await file.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    const rep = await reputation.checkHash(hashHex);

    let risk = "Neutral";
    let details = "No reputation data";

    if (rep.status === 'analyzed') {
        const malicious = rep.data.malicious;
        if (malicious > 0) {
            risk = "High";
            details = `Flagged by ${malicious} vendors on VirusTotal`;
        } else {
            details = "Hash known to VT, no malicious flags";
        }
    } else if (rep.status === 'no_key') {
        risk = "Unknown (No API Key)";
        details = "Reputation check skipped";
    }

    return {
        filename: file.name,
        size: (file.size / 1024).toFixed(2) + ' KB',
        type: file.type || 'unknown',
        hash: hashHex,
        reputation: rep.data,
        risk: risk,
        details: `${details}<br><span style="font-size:0.7em">SHA256: ${hashHex.substring(0, 16)}...</span>`
    };
}

function showLoading(msg = 'Running deep analysis...') {
    const container = document.getElementById('results-container');
    container.style.display = 'block';
    document.getElementById('total-score').innerText = '--';
    document.getElementById('analyst-summary').innerText = msg;
    document.getElementById('sections-wrapper').innerHTML = '';
}

function updateLoading(msg) {
    document.getElementById('analyst-summary').innerText = msg;
}

function displayReport(report, isPartial = false) {
    document.getElementById('total-score').innerText = report.score;
    document.getElementById('analyst-summary').innerText = report.summary;

    let html = '';

    // Anomaly Section
    if (report.anomalies.length > 0) {
        html += `<div class="result-card">
            <div class="card-header"><span class="card-title">Anomalies Detected</span></div>`;
        report.anomalies.forEach(a => {
            html += `<div class="anomaly-item">
                <span class="anomaly-icon">${a.level === 'Critical' ? '🔴' : a.level === 'High' ? '🟠' : '🟡'}</span>
                <div>
                    <strong>${a.level}</strong>: ${a.msg}
                </div>
            </div>`;
        });
        html += `</div>`;
    }

    // Comparison Section
    if (report.comparison && report.comparison.length > 0) {
        html += `<div class="result-card">
            <div class="card-header"><span class="card-title">Comparison Deviations</span></div>`;
        report.comparison.forEach(dev => {
            html += `<div class="anomaly-item">
                <span class="anomaly-icon">⚖️</span>
                <div>${dev}</div>
            </div>`;
        });
        html += `</div>`;
    } else if (report.comparison) {
        html += `<div class="result-card" style="border-color: green;">
            <div class="card-header"><span class="card-title" style="color: green;">Baseline match</span></div>
            <p>No structural deviations detected compared to legitimate sample.</p>
        </div>`;
    }

    // Infrastructure & Path Section
    if (report.infrastructure && report.infrastructure.path) {
        html += `<div class="result-card">
            <div class="card-header"><span class="card-title">Infrastructure Path Analysis</span></div>`;

        // Path Table
        html += `<div class="table-responsive"><table>
            <thead><tr><th>Hop</th><th>IP / Host</th><th>Role</th><th>Status</th></tr></thead>
            <tbody>`;

        report.infrastructure.path.forEach((hop, i) => {
            let statusIcon = '🟢'; // Default transit
            if (hop.role.includes('True Origin')) statusIcon = '🔎';
            else if (hop.isInternal) statusIcon = '🔒';

            html += `<tr>
                <td style="color:#666;">${i + 1}</td>
                <td class="mono">${hop.ip || 'Unknown IP'}<br><span style="font-size:0.7em; color:#888;">${hop.by || ''}</span></td>
                <td><span class="badge ${hop.role.includes('Origin') ? 'badge-blue' : ''}">${hop.role}</span></td>
                <td>${statusIcon}</td>
            </tr>`;
        });
        html += `</tbody></table></div>`;

        // Enrichment Details (ASN/Country)
        if (report.infrastructure.asn !== 'N/A') {
            html += `<div style="margin-top:15px; padding-top:10px; border-top:1px solid #eee;">
                <strong>Origin Context:</strong><br>
                ASN: ${report.infrastructure.asn}<br>
                ISP: ${report.infrastructure.isp}<br>
                Country: ${report.infrastructure.country}<br>
                Risk Assessment: <strong>${report.infrastructure.risk}</strong>
            </div>`;
        }

        html += `</div>`;
    }

    // Other Sections (Auth, etc)
    if (report.sections && report.sections.length > 0) {
        report.sections.forEach(sec => {
            html += `<div class="result-card">
                <div class="card-header"><span class="card-title">${sec.title}</span></div>
                <div style="font-size: 0.85rem;">
                    ${sec.details.map(d => `<div style="margin-bottom: 5px;">${d}</div>`).join('')}
                </div>
                ${sec.deduction > 0 ? `<div style="color: grey; font-size: 0.7rem; margin-top: 10px;">Scoring impact: -${sec.deduction} points</div>` : ''}
            </div>`;
        });
    }

    // Header Table Section
    html += `<div class="result-card">
        <div class="card-header"><span class="card-title">Captured Headers</span></div>
        <div class="table-responsive">
            <table>
                <thead>
                    <tr><th>Header</th><th>Value</th></tr>
                </thead>
                <tbody>`;

    const keyHeaders = ['from', 'to', 'subject', 'date', 'return-path', 'message-id', 'x-mailer'];
    keyHeaders.forEach(key => {
        if (report.rawHeaders[key]) {
            html += `<tr><td>${key}</td><td class="mono">${report.rawHeaders[key]}</td></tr>`;
        }
    });

    html += `</tbody></table></div></div>`;

    document.getElementById('sections-wrapper').innerHTML = html;

    if (isPartial) {
        document.getElementById('analyst-summary').innerHTML += ' <br><br><em>...enriching with reputation data (VT/AbuseIPDB)...</em>';
    }
}

function displayStandaloneResults(title, results) {
    document.getElementById('total-score').innerText = '--';
    document.getElementById('analyst-summary').innerText = `Completed ${title} for ${results.length} items.`;

    let html = '';

    results.forEach(res => {
        const item = res.value || res.ip || res.domain || res.filename;
        let riskIcon = '⚪';
        let riskClass = 'badge-blue';

        if (res.risk === 'High') { riskIcon = '🔴'; riskClass = 'badge-red'; }
        else if (res.risk === 'Medium') { riskIcon = '🟠'; riskClass = 'badge-orange'; }
        else if (res.risk === 'Low' || res.risk.includes('Clean') || res.risk.includes('Neutral')) { riskIcon = '🟢'; riskClass = 'badge-green'; }

        html += `<div class="result-card">
            <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
                <span class="card-title">${item}</span>
                <span class="badge ${riskClass}">${riskIcon} ${res.risk}</span>
            </div>
            <div style="font-size: 0.9rem; padding: 10px 0;">`;

        // IP Specific Layout
        if (res.type === 'IP') {
            const rep = res.data;
            html += `
            <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 15px;">
                <div>
                    <strong>Identity:</strong><br>
                    IP: ${res.value}<br>
                    ASN: ${rep.asn || 'N/A'}<br>
                    ISP: ${rep.isp || 'N/A'}<br>
                    Country: ${rep.country || 'N/A'}
                </div>
                <div>
                    <strong>Reputation Signals:</strong><br>
                    VirusTotal: ${rep.vt.data?.malicious > 0 ? `🔴 ${rep.vt.data.malicious} detections` : '🟢 Clean/Unknown'}<br>
                    AbuseIPDB: ${rep.abuse.data?.score > 0 ? `⚠️ ${rep.abuse.data.score}% confidence` : '🟢 0% confidence'}<br>
                    <small>Last Reported: ${rep.abuse.data?.lastReportedAt || 'N/A'}</small>
                </div>
            </div>`;
        }
        // Domain Specific Layout
        else if (res.type === 'Domain') {
            const data = res.data;
            html += `
            <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 15px;">
                <div>
                    <strong>Context:</strong><br>
                    Domain: ${res.value}<br>
                    A Records: ${data.dns.a.length > 0 ? data.dns.a.length : '0'} found<br>
                    MX Records: ${data.dns.mx.length > 0 ? data.dns.mx.length : '0'} found
                </div>
                <div>
                    <strong>Reputation & Auth:</strong><br>
                    VirusTotal: ${data.reputation.vt.data?.malicious > 0 ? `🔴 ${data.reputation.vt.data.malicious} detections` : '🟢 Clean'}<br>
                    SPF Record: ${data.dns.spf ? '✅ Present' : '❌ Missing'}<br>
                    DMARC Record: ${data.dns.dmarc ? '✅ Present' : '❌ Missing'}
                </div>
            </div>
            <div style="margin-top:10px; border-top:1px solid #eee; padding-top:5px; font-size:0.8rem; color:#666;">
                <strong>Authentciation & DNS Detail:</strong><br>
                MX: ${data.dns.mx.map(m => m.split(' ').pop()).join(', ') || 'None'}<br>
                TXT/SPF: ${data.dns.spf || 'None'}<br>
                DMARC: ${data.dns.dmarc || 'None'}
            </div>`;
        }
        // Attachment (File)
        else if (res.filename) {
            html += `<div style="padding:10px;">${res.details}</div>`;
        }
        // Fallback
        else {
            html += `<div>${res.details}</div>`;
        }

        html += `</div></div>`;
    });

    document.getElementById('sections-wrapper').innerHTML = html;
}
