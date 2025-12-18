class Analyzer {
    constructor(reputationProvider) {
        this.reputation = reputationProvider;
    }

    async lookupDNS(domain, type) {
        try {
            const controller = new AbortController();
            const id = setTimeout(() => controller.abort(), 3000); // 3s DNS timeout
            const response = await fetch(`https://cloudflare-dns.com/query?name=${domain}&type=${type}`, {
                headers: { 'Accept': 'application/dns-json' },
                signal: controller.signal
            });
            clearTimeout(id);
            return await response.json();
        } catch (e) {
            return null;
        }
    }

    // Stage 1: Fast, Synchronous-like Analysis (Headers, Auth, Anomalies)
    async analyzeStatic(headers, compareHeaders = null) {
        const report = {
            timestamp: new Date().toISOString(),
            score: 0, // Calculated later
            sections: [],
            anomalies: [],
            summary: "",
            comparison: null,
            rawHeaders: headers,
            infrastructure: { ip: null, asn: null, isp: null, country: null, risk: 'Unknown' }
        };

        const from = headers['from'] || '';
        const returnPath = headers['return-path'] || '';

        // 1. Authentication Analysis
        const authData = EmailParser.extractAuthResults(headers);
        const authSection = { title: "Authentication Quality", details: [], weight: 40, deduction: 0 };

        // DNS Checks (Async but fast)
        const fromDomain = from.match(/@([^>]+)/)?.[1];
        if (fromDomain) {
            // SPF
            const spfRecord = await this.lookupDNS(fromDomain, 'TXT');
            if (spfRecord && spfRecord.Answer) {
                const record = spfRecord.Answer.find(a => a.data.includes('v=spf1'))?.data;
                if (record) {
                    authSection.details.push(`SPF Policy: ${record}`);
                    if (record.includes('-all')) authSection.details.push("✅ SPF is strict (-all)");
                    else if (record.includes('~all')) authSection.details.push("ℹ️ SPF is soft (~all)");
                    else authSection.details.push("⚠️ SPF is neutral/wide (+all/?all)");
                }
            } else {
                authSection.details.push("ℹ️ No SPF TXT record found via DNS.");
            }

            // DMARC
            const dmarcRecord = await this.lookupDNS(`_dmarc.${fromDomain}`, 'TXT');
            if (dmarcRecord && dmarcRecord.Answer) {
                const record = dmarcRecord.Answer.find(a => a.data.includes('v=DMARC1'))?.data;
                if (record) {
                    authSection.details.push(`DMARC Record: ${record}`);
                    if (record.includes('p=reject')) authSection.details.push("✅ DMARC enforcement: REJECT");
                    else if (record.includes('p=quarantine')) authSection.details.push("✅ DMARC enforcement: QUARANTINE");
                    else {
                        authSection.details.push("⚠️ DMARC enforcement: NONE (Monitoring only)");
                        authSection.deduction += 10;
                    }
                }
            } else {
                authSection.details.push("⚠️ No DMARC record found.");
                authSection.deduction += 10;
            }
        }

        // Header SPF/DKIM Results
        if (authData.spf) {
            authSection.details.push(`SPF Header Result: ${authData.spf}`);
            if (authData.spf !== 'pass') {
                authSection.deduction += 20;
                report.anomalies.push({ level: 'High', msg: `SPF Check Failed: ${authData.spf}` });
            }
        } else {
            authSection.details.push("⚠️ No SPF-Result header found.");
        }

        if (authData.dkim.length > 0) {
            authSection.details.push(`DKIM Signatures: ${authData.dkim.length} present`);
            if (authData.dkim.some(d => d !== 'pass')) {
                authSection.details.push("⚠️ Some DKIM signatures failed verification.");
                authSection.deduction += 10;
            }
        } else {
            authSection.details.push("ℹ️ No DKIM-Signature found.");
        }

        report.sections.push(authSection);

        // 2. Anomaly Detection
        const receivedChain = EmailParser.extractReceivedChain(headers);
        let lastDate = null;
        receivedChain.forEach((hop, index) => {
            if (hop.date && lastDate) {
                if (Math.abs(hop.date - lastDate) > 600000) { // 10 mins
                    report.anomalies.push({ level: 'Low', msg: `Delay of >10 mins at hop ${index}` });
                }
            }
            lastDate = hop.date;
        });

        if (from && returnPath) {
            const fromClean = from.replace(/.*<|>/g, '').trim();
            const rpClean = returnPath.replace(/.*<|>/g, '').trim();
            if (!fromClean.includes(rpClean) && !rpClean.includes(fromClean)) {
                // report.anomalies.push({ level: 'Medium', msg: `From (${fromClean}) != Return-Path (${rpClean})` });
            }
        }

        // Comparison
        if (compareHeaders) {
            report.comparison = this.performComparison(headers, compareHeaders);
        }

        // Prep Infrastructure Data
        const mainIp = receivedChain[0]?.ip;
        report.infrastructure.ip = mainIp;

        // Initial Score (Base 100 - Auth Deductions - Anomaly Deductions)
        report.score = Math.max(0, 100 - authSection.deduction - (report.anomalies.length * 5));

        return report;
    }

    // Stage 2: Reputation Enrichment
    async enrichReport(report) {
        if (!report.infrastructure.ip) return report;

        const infraSection = { title: "Infrastructure Context", details: [], deduction: 0 };
        const rep = await this.reputation.checkIP(report.infrastructure.ip);

        // Update parsed infra data
        report.infrastructure.asn = rep.asn;
        report.infrastructure.isp = rep.isp;
        report.infrastructure.country = rep.country;

        infraSection.details.push(`Origin IP: ${report.infrastructure.ip}`);
        infraSection.details.push(`ASN: ${rep.asn} | Org: ${rep.isp}`);
        infraSection.details.push(`Country: ${rep.country}`);

        // Scenarios
        let riskLabel = "Neutral";

        // VT Analysis
        if (rep.vt.status === 'analyzed') {
            const malicious = rep.vt.data.malicious;
            infraSection.details.push(`VirusTotal: ${malicious} vendors flagged this IP.`);
            if (malicious > 0) {
                infraSection.deduction += (malicious * 10);
                report.anomalies.push({ level: 'Critical', msg: `IP flagged by ${malicious} security vendors.` });
                riskLabel = "High";
            }
        } else if (rep.vt.status === 'no_key') {
            infraSection.details.push("ℹ️ VirusTotal lookup skipped (No API Key).");
        }

        // AbuseIPDB Analysis
        if (rep.abuse.status === 'analyzed') {
            const score = rep.abuse.data.score;
            infraSection.details.push(`AbuseIPDB Confidence: ${score}%`);
            if (score > 50) {
                infraSection.deduction += 30;
                riskLabel = "High";
            } else if (score > 20) {
                infraSection.deduction += 10;
                if (riskLabel !== "High") riskLabel = "Medium";
            }
        }

        // Contextual Interpretation
        const lowerIsp = (rep.isp || '').toLowerCase();
        if (lowerIsp.includes('amazon') || lowerIsp.includes('google cloud') || lowerIsp.includes('microsoft corporation') || lowerIsp.includes('digitalocean')) {
            infraSection.details.push("📝 Analyst Note: IP belongs to a major cloud provider. While legitimate, cloud IPs are often used for ephemeral relays.");
        } else if (lowerIsp === 'unknown') {
            infraSection.details.push("📝 Analyst Note: ISP identity could not be resolved.");
        }

        report.sections.push(infraSection);
        report.score = Math.max(0, report.score - infraSection.deduction);
        report.infrastructure.risk = riskLabel;
        report.summary = this.generateSummary(report);

        return report;
    }

    generateSummary(report) {
        let text = `Analysis yielded a risk score of ${report.score}/100. `;

        if (report.score < 50) {
            return text + "Critical indicators found. The email demonstrates significant authentication failures or originates from high-risk infrastructure. Treat with extreme caution.";
        } else if (report.score < 80) {
            return text + "Suspicious signals detected. While some checks passed, there are anomalies in authentication or infrastructure reputation that warrant manual review.";
        } else {
            return text + "The email aligns with standard authentication policies and originates from neutral infrastructure. No overt malicious indicators were found, but verify context.";
        }
    }

    performComparison(headers, compareHeaders) {
        const deviations = [];
        // Comparison logic same as before...
        const chain1 = EmailParser.extractReceivedChain(headers);
        const chain2 = EmailParser.extractReceivedChain(compareHeaders);
        if (Math.abs(chain1.length - chain2.length) > 1) {
            deviations.push(`Hop count mismatch: Analyzed has ${chain1.length}, Known has ${chain2.length}.`);
        }
        return deviations;
    }

    async analyzeIPs(ips) {
        const results = [];
        for (const ip of ips) {
            if (!ip.trim()) continue;
            const rep = await this.reputation.checkIP(ip.trim());
            // Interpret result
            let risk = "Neutral";
            let details = rep.isp || 'Unknown ISP';

            if (rep.vt.data?.malicious > 0 || rep.abuse.data?.score > 50) risk = "High";
            else if (rep.abuse.data?.score > 20) risk = "Medium";

            if (rep.vt.status === 'no_key' && rep.abuse.status === 'no_key') risk = "Unknown (No Keys)";

            results.push({ ip: ip.trim(), reputation: rep, risk: risk, details: details });
        }
        return results;
    }

    async analyzeDomains(domains) {
        const results = [];
        for (const d of domains) {
            if (!d.trim()) continue;
            const rep = await this.reputation.checkDomain(d.trim());
            let risk = "Neutral";
            if (rep.vt.data?.malicious > 0) risk = "High";
            if (rep.vt.status === 'no_key') risk = "Unknown (No Keys)";

            results.push({ domain: d.trim(), reputation: rep, risk: risk });
        }
        return results;
    }
}
