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

    // Helper: Full Domain Profile (DNS + Reputation)
    async _getDomainProfile(domain) {
        const profile = { domain: domain, dns: {}, reputation: null, risk: 'Unknown' };

        // 1. DNS Recon (Parallel)
        const dnsTypes = ['A', 'MX', 'TXT'];
        const dnsPromises = dnsTypes.map(t => this.lookupDNS(domain, t));
        const [a, mx, txt] = await Promise.all(dnsPromises);

        profile.dns.a = a?.Answer?.map(x => x.data) || [];
        profile.dns.mx = mx?.Answer?.map(x => x.data) || [];
        profile.dns.txt = txt?.Answer?.map(x => x.data) || [];

        // Parsing SPF/DMARC from TXT (simplified for profile)
        profile.dns.spf = profile.dns.txt.find(t => t.includes('v=spf1')) || null;

        // DMARC specific lookup
        const dmarc = await this.lookupDNS(`_dmarc.${domain}`, 'TXT');
        profile.dns.dmarc = dmarc?.Answer?.find(x => x.data.includes('v=DMARC1'))?.data || null;

        // 2. Reputation
        profile.reputation = await this.reputation.checkDomain(domain);

        // 3. Risk Derivation
        if (profile.reputation.vt.data?.malicious > 0) profile.risk = "High";
        else if (profile.reputation.vt.status === 'analyzed') profile.risk = "Neutral (Clean)";

        return profile;
    }

    // Stage 1: Fast, Synchronous-like Analysis (Headers, Auth, Anomalies)
    async analyzeStatic(headers, compareHeaders = null) {
        const report = {
            timestamp: new Date().toISOString(),
            score: 0,
            sections: [],
            anomalies: [],
            summary: "",
            comparison: null,
            rawHeaders: headers,
            infrastructure: {
                ip: null,
                path: [],
                asn: 'N/A',
                isp: 'N/A',
                country: 'N/A',
                risk: 'Unknown'
            }
        };

        const from = headers['from'] || '';
        const returnPath = headers['return-path'] || '';
        const receivedChain = EmailParser.extractReceivedChain(headers); // [Origin ... Recipient]

        // 1. Path Analysis & True Origin Detection
        const internalIps = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|fc00:|fe80:)/;
        let originHop = null;

        // Path Classification
        report.infrastructure.path = receivedChain.map((hop, i) => {
            const isInternal = hop.ip ? internalIps.test(hop.ip) : false;
            let role = 'Transit';

            if (i === 0) role = 'Origin (Claimed)';
            if (i === receivedChain.length - 1) role = 'Recipient MX';

            // Heuristic for True Origin: First Public IP
            if (!originHop && hop.ip && !isInternal) {
                originHop = hop;
                role = 'True Origin (First Public)';
            }

            return { ...hop, role: role, isInternal: isInternal };
        });

        // Fallback if no public IP found (internal only chain)
        if (!originHop && receivedChain.length > 0) originHop = receivedChain[0];

        // Set Main IP for Enrichment
        report.infrastructure.ip = originHop ? originHop.ip : null;

        // 2. Authentication Analysis (Strict)
        const authData = EmailParser.extractAuthResults(headers);
        const authSection = { title: "Authentication Quality", details: [], weight: 40, deduction: 0 };

        // Header Results (Trust but Verify)
        if (authData.spf) {
            authSection.details.push(`SPF Header: ${authData.spf}`);
            if (authData.spf !== 'pass') {
                authSection.deduction += 20;
                report.anomalies.push({ level: 'High', msg: `SPF Header Failed: ${authData.spf}` });
            }
        } else {
            authSection.details.push("⚠️ No SPF-Result header.");
            authSection.deduction += 10;
        }

        if (authData.dkim.length > 0) {
            authSection.details.push(`DKIM Signatures: ${authData.dkim.length} found`);
            if (!authData.dkim.some(d => d === 'pass')) {
                authSection.deduction += 10;
                report.anomalies.push({ level: 'Medium', msg: "DKIM Verification Failed" });
            }
        } else {
            authSection.details.push("⚠️ No DKIM-Signature found.");
            authSection.deduction += 10;
        }

        // DNS-based Auth Checks (Async)
        const fromDomain = from.match(/@([^>]+)/)?.[1];
        if (fromDomain) {
            // SPF Record Check
            const spfRecord = await this.lookupDNS(fromDomain, 'TXT');
            let spfFound = false;
            if (spfRecord && spfRecord.Answer) {
                const record = spfRecord.Answer.find(a => a.data.includes('v=spf1'))?.data;
                if (record) {
                    spfFound = true;
                    authSection.details.push(`SPF Policy: ${record}`);
                    if (record.includes('+all') || record.includes('?all')) {
                        authSection.details.push("⚠️ Weak SPF Policy (+all/?all)");
                        authSection.deduction += 10;
                    }
                }
            }
            if (!spfFound) {
                authSection.details.push("🔴 No SPF TXT record found.");
                authSection.deduction += 20;
            }

            // DMARC Record Check
            const dmarcRecord = await this.lookupDNS(`_dmarc.${fromDomain}`, 'TXT');
            let dmarcFound = false;
            if (dmarcRecord && dmarcRecord.Answer) {
                const record = dmarcRecord.Answer.find(a => a.data.includes('v=DMARC1'))?.data;
                if (record) {
                    dmarcFound = true;
                    authSection.details.push(`DMARC Policy: ${record}`);
                    if (record.includes('p=none')) {
                        authSection.details.push("⚠️ DMARC Policy is NONE (No enforcement)");
                        authSection.deduction += 10;
                    }
                    if (record.includes('p=reject') || record.includes('p=quarantine')) {
                        authSection.details.push("✅ DMARC Enforcement Active");
                    }
                }
            }
            if (!dmarcFound) {
                authSection.details.push("🔴 No DMARC Record found.");
                authSection.deduction += 15;
            }
        }

        report.sections.push(authSection);

        // 3. Sender Alignment
        if (from && returnPath) {
            const fromClean = from.replace(/.*<|>/g, '').trim();
            const rpClean = returnPath.replace(/.*<|>/g, '').trim();
            if (!fromClean.includes(rpClean) && !rpClean.includes(fromClean)) {
                // report.anomalies.push({ level: 'Medium', msg: `Mismatch: From <${fromClean}> vs Return-Path <${rpClean}>` });
            }
        }

        // 4. Comparison
        if (compareHeaders) {
            report.comparison = this.performComparison(headers, compareHeaders);
        }

        // Initial Score
        report.score = Math.max(0, 100 - authSection.deduction - (report.anomalies.length * 5));

        return report;
    }

    // Stage 2: Reputation Enrichment
    async enrichReport(report) {
        if (report.infrastructure.ip) {
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
            if (rep.vt.status === 'analyzed') {
                const malicious = rep.vt.data.malicious;
                infraSection.details.push(`VirusTotal: ${malicious} vendors flagged this IP.`);
                if (malicious > 0) {
                    infraSection.deduction += (malicious * 10);
                    report.anomalies.push({ level: 'Critical', msg: `Origin IP flagged by ${malicious} security vendors.` });
                    riskLabel = "High";
                }
            } else if (rep.vt.status === 'no_key') {
                infraSection.details.push("ℹ️ VirusTotal lookup skipped (No API Key).");
            }

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

            report.sections.push(infraSection);
            report.score = Math.max(0, report.score - infraSection.deduction);
            report.infrastructure.risk = riskLabel;
        }

        // 2. Sender Domain Context (NEW)
        const from = report.rawHeaders['from'] || '';
        const domain = from.match(/@([^>]+)/)?.[1];
        if (domain) {
            const domProfile = await this._getDomainProfile(domain);
            const domSection = { title: "Sender Domain Profile", details: [], deduction: 0 };

            domSection.details.push(`<strong>${domain}</strong>`);
            domSection.details.push(`A Records: ${domProfile.dns.a.length > 0 ? domProfile.dns.a.join(', ') : 'None'}`);
            domSection.details.push(`MX Records: ${domProfile.dns.mx.length > 0 ? domProfile.dns.mx.map(m => m.split(' ').pop()).join(', ') : 'None'}`);

            if (domProfile.reputation.vt.data) {
                const age = domProfile.reputation.vt.data.creation_date
                    ? Math.floor((Date.now() / 1000 - domProfile.reputation.vt.data.creation_date) / 86400) + ' days'
                    : 'Unknown';
                domSection.details.push(`Domain Age: ${age}`);
                if (domProfile.reputation.vt.data.malicious > 0) {
                    domSection.details.push(`🔴 VirusTotal: ${domProfile.reputation.vt.data.malicious} detections`);
                    domSection.deduction += 20;
                } else {
                    domSection.details.push(`🟢 VirusTotal: Clean`);
                }
            } else {
                domSection.details.push(`⚪ Reputation: No Data`);
            }

            report.sections.push(domSection);
            report.score = Math.max(0, report.score - domSection.deduction);
        }

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
            // Full reputation lookup
            const rep = await this.reputation.checkIP(ip.trim());

            // Derive risk but keep full details
            let risk = "Neutral";
            let details = rep.isp || 'Unknown ISP';

            if (rep.vt.data?.malicious > 0 || rep.abuse.data?.score > 50) risk = "High";
            else if (rep.abuse.data?.score > 20) risk = "Medium";

            if (rep.vt.status === 'no_key' && rep.abuse.status === 'no_key') risk = "Unknown (No Keys)";

            results.push({
                type: 'IP',
                value: ip.trim(),
                data: rep,
                risk: risk
            });
        }
        return results;
    }

    async analyzeDomains(domains) {
        const results = [];
        for (const d of domains) {
            if (!d.trim()) continue;
            // Full Profile lookup
            const profile = await this._getDomainProfile(d.trim());
            results.push({
                type: 'Domain',
                value: d.trim(),
                data: profile,
                risk: profile.risk
            });
        }
        return results;
    }
}
