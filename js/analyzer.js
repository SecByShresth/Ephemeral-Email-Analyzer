class Analyzer {
    constructor(reputationProvider) {
        this.reputation = reputationProvider;
    }

    async lookupDNS(domain, type) {
        try {
            const response = await fetch(`https://cloudflare-dns.com/query?name=${domain}&type=${type}`, {
                headers: { 'Accept': 'application/dns-json' }
            });
            return await response.json();
        } catch (e) {
            console.error(`DNS lookup failed for ${domain} ${type}`, e);
            return null;
        }
    }

    async analyzeFull(headers, compareHeaders = null) {
        const report = {
            timestamp: new Date().toISOString(),
            score: 100,
            sections: [],
            anomalies: [],
            summary: "",
            comparison: null,
            rawHeaders: headers
        };

        const from = headers['from'] || '';
        const returnPath = headers['return-path'] || '';

        // 1. Authentication Analysis
        const authData = EmailParser.extractAuthResults(headers);
        const authSection = {
            title: "Authentication Quality",
            details: [],
            weight: 40,
            deduction: 0
        };

        // Deep DNS-based checks
        const fromDomain = from.match(/@([^>]+)/)?.[1];
        if (fromDomain) {
            const spfRecord = await this.lookupDNS(fromDomain, 'TXT');
            if (spfRecord && spfRecord.Answer) {
                const record = spfRecord.Answer.find(a => a.data.includes('v=spf1'))?.data;
                if (record) {
                    authSection.details.push(`SPF Policy: ${record}`);
                    if (record.includes('-all')) {
                        authSection.details.push("✅ SPF policy is strict (-all)");
                    } else if (record.includes('~all')) {
                        authSection.details.push("ℹ️ SPF policy is soft (~all)");
                    }

                    const lookupCount = (record.match(/include:|a:|mx:|ptr:|exists:|redirect=/g) || []).length;
                    if (lookupCount > 10) {
                        report.anomalies.push({ level: 'Medium', msg: `SPF record exceeds 10 DNS lookups (${lookupCount})` });
                        authSection.deduction += 5;
                    }
                }
            }

            const dmarcRecord = await this.lookupDNS(`_dmarc.${fromDomain}`, 'TXT');
            if (dmarcRecord && dmarcRecord.Answer) {
                const record = dmarcRecord.Answer.find(a => a.data.includes('v=DMARC1'))?.data;
                if (record) {
                    authSection.details.push(`DMARC Record: ${record}`);
                    if (record.includes('p=reject')) {
                        authSection.details.push("✅ DMARC policy is set to REJECT");
                    } else if (record.includes('p=none')) {
                        report.anomalies.push({ level: 'Low', msg: "DMARC policy set to 'none' (monitoring only)" });
                        authSection.deduction += 5;
                    }
                }
            }
        }

        // SPF Check
        if (authData.spf) {
            authSection.details.push(`SPF: ${authData.spf}`);
            if (authData.spf !== 'pass') {
                authSection.deduction += 15;
                report.anomalies.push({ level: 'High', msg: `SPF Check Failed (${authData.spf})` });
            }
        } else {
            authSection.deduction += 20;
            report.anomalies.push({ level: 'High', msg: "Missing SPF Authentication" });
        }

        // DMARC Check
        if (authData.dmarc) {
            authSection.details.push(`DMARC: ${authData.dmarc}`);
            if (authData.dmarc !== 'pass') {
                authSection.deduction += 10;
            }
        } else {
            authSection.deduction += 15;
            report.anomalies.push({ level: 'Medium', msg: "Missing DMARC Policy" });
        }
        report.sections.push(authSection);

        // 2. Header Anomaly Detection
        const internalIps = ['127.0.0.1', '10.', '172.16.', '192.168.'];
        const receivedChain = EmailParser.extractReceivedChain(headers);

        let lastDate = null;
        receivedChain.forEach((hop, index) => {
            // Check for timestamp drift
            if (hop.date && lastDate) {
                const diff = Math.abs(hop.date - lastDate);
                if (diff > 300000) { // 5 minutes
                    report.anomalies.push({ level: 'Low', msg: `Significant timestamp drift detected at hop ${index}` });
                }
            }
            lastDate = hop.date;

            // Check for private IPs in transit (excluding start/end potentially)
            if (hop.ip && index > 0 && index < receivedChain.length - 1) {
                if (internalIps.some(prefix => hop.ip.startsWith(prefix))) {
                    report.anomalies.push({ level: 'Medium', msg: `Private IP ${hop.ip} detected in transit chain` });
                }
            }
        });

        // Sender Alignment
        if (from && returnPath && !from.includes(returnPath.replace(/[<>]/g, ''))) {
            report.anomalies.push({ level: 'Medium', msg: "From / Return-Path Mismatch" });
        }

        // 3. Infrastructure Reputation
        const infraSection = { title: "Infrastructure Reputation", details: [], weight: 30, deduction: 0 };
        const mainIp = receivedChain[0]?.ip; // Usually the first relay
        if (mainIp) {
            const rep = await this.reputation.checkIP(mainIp);
            if (rep.vt && rep.vt.malicious > 0) {
                infraSection.deduction += 20;
                report.anomalies.push({ level: 'Critical', msg: `Sending IP ${mainIp} flagged on VirusTotal` });
            }
            if (rep.abuse && rep.abuse.score > 20) {
                infraSection.deduction += 10;
                report.anomalies.push({ level: 'High', msg: `Sending IP ${mainIp} has high abuse score: ${rep.abuse.score}%` });
            }
            infraSection.details.push(`Primary Relay IP: ${mainIp} (${rep.asn || 'Unknown ASN'})`);
        }
        report.sections.push(infraSection);

        // 4. Comparison Mode
        if (compareHeaders) {
            report.comparison = this.performComparison(headers, compareHeaders);
        }

        // Finalize Scoring
        report.score = Math.max(0, 100 - authSection.deduction - infraSection.deduction - (report.anomalies.length * 5));

        // Generate Summary
        report.summary = this.generateSummary(report, authData);

        return report;
    }

    performComparison(headers, compareHeaders) {
        const deviations = [];
        const keys = ['x-mailer', 'user-agent', 'content-type', 'mime-version'];

        keys.forEach(key => {
            const h1 = (headers[key] || '').toLowerCase();
            const h2 = (compareHeaders[key] || '').toLowerCase();
            if (h1 && h2 && h1 !== h2) {
                deviations.push(`Structural deviation in ${key}: Expected patterns matching legitimate sample were not found.`);
            }
        });

        // Compare hop count
        const chain1 = EmailParser.extractReceivedChain(headers);
        const chain2 = EmailParser.extractReceivedChain(compareHeaders);
        if (Math.abs(chain1.length - chain2.length) > 2) {
            deviations.push("Significant variation in relay hop count compared to legitimate baseline.");
        }

        return deviations;
    }

    generateSummary(report, authData) {
        if (report.score > 80) {
            return "This email passed most authentication checks and shows clean infrastructure reputation. It appears legitimate based on header analysis.";
        } else if (report.score > 50) {
            return "Analysis shows some red flags. Authentication records might be incomplete or the infrastructure has minor reputation issues. Proceed with caution.";
        } else {
            return "CAUTION: This email shows significant anomalies. Multiple authentication failures or poor infrastructure reputation detected. High risk of spoofing or phishing.";
        }
    }

    async analyzeIPs(ips) {
        const results = [];
        for (const ip of ips) {
            const trimmed = ip.trim();
            if (!trimmed) continue;
            const rep = await this.reputation.checkIP(trimmed);
            results.push({
                ip: trimmed,
                reputation: rep,
                risk: (rep.abuse?.score > 20 || (rep.vt && rep.vt.malicious > 0)) ? 'High' : 'Low'
            });
        }
        return results;
    }

    async analyzeDomains(domains) {
        const results = [];
        for (const domain of domains) {
            const trimmed = domain.trim();
            if (!trimmed) continue;
            const rep = await this.reputation.checkDomain(trimmed);
            results.push({
                domain: trimmed,
                reputation: rep,
                risk: (rep.vt && rep.vt.malicious > 0) ? 'High' : 'Low'
            });
        }
        return results;
    }
}
