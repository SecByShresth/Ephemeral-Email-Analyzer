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
    document.getElementById('total-score').innerText = report.riskScore;
    document.getElementById('analyst-summary').innerText = report.summary;

    let html = '';

    // --- RENDER MODULES ---

    // 1. Identity & Spoofing
    const modId = report.modules.identity;
    html += `<div class="result-card">
        <div class="card-header"><span class="card-title">1. Identity & Spoofing</span></div>
        <div style="padding:10px;">
            ${renderIssues(modId.issues)}
            <div style="margin-top:10px; display:grid; grid-template-columns: 1fr 1fr; gap:10px;">
                <div>
                    <strong>Authentication:</strong><br>
                    SPF: ${modId.data.auth?.spf || 'None'} ${modId.data.auth?.spf === 'pass' ? '✅' : '❌'}<br>
                    DKIM: ${modId.data.auth?.dkim?.join(', ') || 'None'} ${modId.data.auth?.dkim?.includes('pass') ? '✅' : '❌'}<br>
                    DMARC: ${modId.data.auth?.dmarc || 'None'}
                </div>
            </div>
        </div>
    </div>`;

    // 2. Infrastructure & Routing (MS Style + Reputation)
    const modInfra = report.modules.infrastructure;
    html += `<div class="result-card">
        <div class="card-header"><span class="card-title">2. Infrastructure & Routing</span></div>
        <div style="padding:10px;">
            ${renderIssues(modInfra.issues)}
            <p><strong>Total Hops:</strong> ${modInfra.data.hops.length}</p>
            
            <div class="table-responsive">
                <table>
                    <thead><tr><th>Hop</th><th>Delay</th><th>From (Sending)</th><th>By (Receiving)</th><th>IP / Reputation</th></tr></thead>
                    <tbody>
                        ${modInfra.data.hops.map(h => {
        // Highlight origin
        let ipStyle = '';
        if (h.role === 'True Origin (First Public)') ipStyle = 'font-weight:bold; color:#0af;';

        return `<tr>
                            <td>${h.number}</td>
                            <td>${h.delay ? h.delay + 's' : '-'}</td>
                            <td class="mono">${h.from || ''}</td>
                            <td class="mono">${h.by || ''}</td>
                            <td class="mono" style="${ipStyle}">${h.ip || ''}</td>
                        </tr>`}).join('')}
                    </tbody>
                </table>
            </div>
            <div style="margin-top:10px;">
                 <strong>True Origin IP:</strong> ${modInfra.data.originIp || 'Unknown'}
            </div>
        </div>
    </div>`;

    // 3. Threat Intelligence
    const modThreat = report.modules.threatIntel;
    html += `<div class="result-card">
        <div class="card-header"><span class="card-title">3. Threat Intelligence</span></div>
        <div style="padding:10px;">
            ${renderIssues(modThreat.issues)}
            <div style="display:grid; grid-template-columns: 1fr 1fr; gap:20px;">
                <div>
                    <strong>Origin IP Reputation:</strong><br>
                    ${renderReputation(modThreat.data.originReputation)}
                </div>
                <div>
                    <strong>Sender Domain Profile:</strong><br>
                    ${renderDomainProfile(modThreat.data.senderDomain)}
                </div>
            </div>
        </div>
    </div>`;

    // 4 & 5. Content & Vendor
    const modContent = report.modules.content;
    const modVendor = report.modules.vendor;
    html += `<div class="result-card">
        <div class="card-header"><span class="card-title">4. Content & Vendor Specs</span></div>
        <div style="padding:10px; display:grid; grid-template-columns: 1fr 1fr; gap:20px;">
            <div>
                 <strong>Content Metadata:</strong><br>
                 MIME: ${modContent.data.mime}<br>
                 Encoding: ${modContent.data.encoding || 'Standard'}<br>
                 Attachments: ${modContent.data.hasAttachments ? 'Yes 📎' : 'No'}
            </div>
            <div>
                 <strong>Vendor Headers:</strong><br>
                 Microsoft SCL: ${modVendor.data.microsoft || 'N/A'}<br>
                 Google DKIM: ${modVendor.data.google || 'N/A'}
            </div>
        </div>
    </div>`;

    // Headers Table
    html += `<div class="result-card">
        <div class="card-header"><span class="card-title">Raw Headers</span></div>
        <div class="table-responsive" style="max-height: 400px; overflow-y:auto;">
            <table>
                <thead><tr><th>Header</th><th>Value</th></tr></thead>
                <tbody>
                ${Object.keys(report.rawHeaders).map(k => {
        let val = report.rawHeaders[k];
        if (Array.isArray(val)) val = val.join('<br>'); // Handle array headers

        // Safe truncation for rendering massive headers
        const displayVal = val.length > 300
            ? `<div style="max-width:500px; overflow-wrap:anywhere;">${val}</div>`
            : val;

        return `<tr><td style="width:150px;">${k}</td><td class="mono">${displayVal}</td></tr>`;
    }).join('')}
                </tbody>
            </table>
        </div>
    </div>`;

    document.getElementById('sections-wrapper').innerHTML = html;

    if (isPartial) {
        document.getElementById('analyst-summary').innerHTML += ' <br><em>...enriching with Threat Intel...</em>';
    }
}

function renderIssues(issues) {
    if (!issues || issues.length === 0) return '<div style="color:green; margin-bottom:10px;">✅ No Issues Detected</div>';
    return issues.map(i => {
        let color = 'gold';
        if (i.level === 'Critical') color = 'red';
        else if (i.level === 'High') color = 'orange';
        return `<div style="background: rgba(255,255,255,0.05); padding:5px; border-left: 3px solid ${color}; margin-bottom:5px;">
            <strong>${i.level}:</strong> ${i.msg}
        </div>`;
    }).join('');
}

function renderReputation(rep) {
    if (!rep) return "Pending...";
    const vt = rep.vt.data?.malicious;
    return `
    ASN: ${rep.asn || 'N/A'}<br>
    ISP: ${rep.isp || 'N/A'}<br>
    Country: ${rep.country || 'N/A'}<br>
    VirusTotal: ${vt !== undefined ? (vt > 0 ? `🔴 ${vt} Detections` : '🟢 Clean') : 'N/A'}
    `;
}

function renderDomainProfile(prof) {
    if (!prof) return "Pending...";
    return `
    Domain: ${prof.domain}<br>
    Age: ${prof.ageDays !== null ? prof.ageDays + ' days' : 'Unknown'}<br>
    MX Records: ${prof.dns.mx.length}<br>
    VirusTotal: ${prof.reputation?.vt?.data?.malicious > 0 ? '🔴 Malicious' : '🟢 Clean'}
    `;
}

function displayStandaloneResults(title, results) {
    document.getElementById('total-score').innerText = '--';
    document.getElementById('analyst-summary').innerText = `Completed ${title} for ${results.length} items.`;

    let html = '';

    results.forEach(res => {
        // Handle simple file analysis which hasn't changed structure
        if (res.filename) {
            html += `<div class="result-card">
                <div class="card-header"><span class="card-title">${res.filename}</span></div>
                <div style="padding:10px;">${res.details}</div>
            </div>`;
            return;
        }

        const risk = res.risk;
        let riskColor = 'green';
        let riskIcon = '🟢';
        if (risk.level === 'Red') { riskColor = 'red'; riskIcon = '🔴'; }
        else if (risk.level === 'Yellow') { riskColor = 'orange'; riskIcon = '🟡'; }

        html += `<div class="result-card" style="border-left: 5px solid ${riskColor};">
            <div class="card-header" style="display:flex; justify-content:space-between; align-items:center;">
                <span class="card-title" style="font-size:1.2em;">${res.value}</span>
                <span class="badge" style="background:${riskColor}; color:white;">${riskIcon} ${risk.level.toUpperCase()} RISK</span>
            </div>
            
            <div style="padding:0 15px 15px 15px;">`;

        // Render Flags if any
        if (risk.flags && risk.flags.length > 0) {
            html += `<div style="margin: 10px 0; padding: 10px; background: rgba(255,255,255,0.05); border-radius: 4px;">
                <strong>⚠️ Detection Flags:</strong>
                <ul style="margin: 5px 0 0 20px; padding:0; color:${riskColor === 'red' ? '#ff6b6b' : '#feca57'};">
                    ${risk.flags.map(f => `<li>${f}</li>`).join('')}
                </ul>
            </div>`;
        } else {
            html += `<div style="margin: 10px 0; padding: 10px; background: rgba(0,255,0,0.1); border-radius: 4px; color: #badc58;">
                <strong>✅ Clean Identity:</strong> No immediate threat indicators found.
            </div>`;
        }

        // IP Layout
        if (res.type === 'IP') {
            html += `
            <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top:10px;">
                <div>
                    <h4 style="border-bottom:1px solid #444; padding-bottom:5px; margin-bottom:10px;">A. Identity & Infrastructure</h4>
                    <div style="font-size:0.9em; line-height:1.6;">
                        <strong>ISP / Org:</strong> ${res.identity.isp}<br>
                        <strong>ASN:</strong> ${res.identity.asn}<br>
                        <strong>PTR Record:</strong> ${res.identity.ptr || 'None'} <br>
                        <strong>Type:</strong> ${res.identity.version}
                    </div>
                </div>
                <div>
                     <h4 style="border-bottom:1px solid #444; padding-bottom:5px; margin-bottom:10px;">B. Geolocation & Usage</h4>
                     <div style="font-size:0.9em; line-height:1.6;">
                        <strong>Location:</strong> ${res.geo.country}<br>
                        <strong>Usage Type:</strong> ${res.geo.usage || 'Unknown'}<br>
                        <strong>Abuse Score:</strong> ${res.risk.abuseScore}%<br>
                        <strong>Blacklist:</strong> ${res.risk.blacklist}
                     </div>
                </div>
            </div>`;
        }

        // Domain Layout
        if (res.type === 'Domain') {
            html += `
            <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top:10px;">
                <div>
                    <h4 style="border-bottom:1px solid #444; padding-bottom:5px; margin-bottom:10px;">A. Identity (WHOIS)</h4>
                    <div style="font-size:0.9em; line-height:1.6;">
                        <strong>Registrar:</strong> ${res.identity.registrar}<br>
                        <strong>Created:</strong> ${res.identity.created}<br>
                        <strong>Age:</strong> ${res.identity.ageDays !== null ? res.identity.ageDays + ' days' : 'Unknown'}<br>
                        <strong>Category:</strong> ${res.content.category}
                    </div>
                </div>
                <div>
                     <h4 style="border-bottom:1px solid #444; padding-bottom:5px; margin-bottom:10px;">B. Infrastructure (DNS)</h4>
                     <div style="font-size:0.9em; line-height:1.6;">
                        <strong>A Records:</strong> ${res.dns.a.length} IPs found<br>
                        <strong>MX Records:</strong> ${res.dns.mx.length > 0 ? '✅ Present' : '❌ Missing'}<br>
                        <strong>SPF:</strong> ${res.dns.spf ? '✅ Present' : '❌ Missing'}<br>
                        <strong>DMARC:</strong> ${res.dns.dmarc ? '✅ Present' : '❌ Missing'}
                     </div>
                </div>
            </div>
            
            <div style="margin-top:15px;">
                 <h4 style="border-bottom:1px solid #444; padding-bottom:5px; margin-bottom:10px;">DNS Map</h4>
                 <div style="background:#111; padding:10px; border-radius:4px; font-family:monospace; font-size:0.85em; color:#ccc;">
                    NS: ${res.dns.ns.join(', ') || 'None'}<br>
                    MX: ${res.dns.mx.map(m => m.split(' ').pop()).join(', ') || 'None'}<br>
                    AAAA: ${res.dns.aaaa.join(', ') || 'None'}
                 </div>
            </div>`;
        }

        html += `</div></div>`;
    });

    document.getElementById('sections-wrapper').innerHTML = html;
}
