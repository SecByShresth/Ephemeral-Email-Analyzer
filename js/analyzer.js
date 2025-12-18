class Analyzer {
    constructor(reputationProvider) {
        this.reputation = reputationProvider;
    }

    async lookupDNS(domain, type) {
        try {
            const controller = new AbortController();
            setTimeout(() => controller.abort(), 3000);
            const res = await fetch(`https://cloudflare-dns.com/query?name=${domain}&type=${type}`, {
                headers: { 'Accept': 'application/dns-json' },
                signal: controller.signal
            });
            return await res.json();
        } catch { return null; }
    }

    // Helper: calculate time difference in seconds between two dates
    _calcDelay(date1, date2) {
        if (!date1 || !date2) return null;
        const d1 = new Date(date1);
        const d2 = new Date(date2);
        if (isNaN(d1) || isNaN(d2)) return null;
        return Math.round((d1 - d2) / 1000);
    }

    async analyzeStatic(headers, compareHeaders = null) {
        // Initialize 6-Module structure
        const report = {
            timestamp: new Date().toISOString(),
            riskScore: 100, // Starts at 100 (Safe), decreases with risk
            modules: {
                identity: { title: "Identity & Spoofing", issues: [], data: {} },
                infrastructure: { title: "Infrastructure & Routing", issues: [], data: { hops: [] } },
                threatIntel: { title: "Threat Intelligence", issues: [], data: {} },
                content: { title: "Content & Payload", issues: [], data: {} },
                vendor: { title: "Vendor Specifics", issues: [], data: {} }
            },
            summary: "",
            rawHeaders: headers
        };

        const fromNum = headers['from'] || '';
        const returnPath = headers['return-path'] || '';
        const replyTo = headers['reply-to'] || '';

        // --- MODULE 1: Identity & Spoofing ---
        const fromEmail = fromNum.match(/<(.+)>/)?.[1] || fromNum;
        const fromDomain = fromEmail.includes('@') ? fromEmail.split('@')[1] : '';

        // 1. Alignment Checks
        if (returnPath) {
            const rpEmail = returnPath.match(/<(.+)>/)?.[1] || returnPath;
            if (fromDomain && !rpEmail.includes(fromDomain)) {
                report.riskScore -= 20;
                report.modules.identity.issues.push({ level: 'High', msg: `Envelope Mismatch: Return-Path <${rpEmail}> does not match From domain.` });
            }
        }
        if (replyTo) {
            const rtEmail = replyTo.match(/<(.+)>/)?.[1] || replyTo;
            if (fromDomain && !rtEmail.includes(fromDomain)) {
                report.riskScore -= 20;
                report.modules.identity.issues.push({ level: 'Critical', msg: `Reply-To Mismatch: Replies go to <${rtEmail}>, different from sender.` });
            }
        }

        // 2. Homograph / Punycode Check
        if (fromDomain && fromDomain.startsWith('xn--')) {
            report.riskScore -= 15;
            report.modules.identity.issues.push({ level: 'High', msg: `Punycode Domain Detected: ${fromDomain} (Potential Homograph Attack)` });
        }

        // 3. Authentication (SPF/DKIM/DMARC/ARC)
        const auth = EmailParser.extractAuthResults(headers);
        report.modules.identity.data.auth = auth;

        if (auth.spf && auth.spf !== 'pass') {
            report.riskScore -= 30;
            report.modules.identity.issues.push({ level: 'Critical', msg: `SPF Failed: ${auth.spf}` });
        }
        if (auth.dkim.length > 0 && !auth.dkim.includes('pass')) {
            report.riskScore -= 20; // Penalize if DKIM exists but fails
            report.modules.identity.issues.push({ level: 'High', msg: 'DKIM Verification Failed' });
        }

        // --- MODULE 2: Infrastructure & Routing ---
        const hops = EmailParser.extractReceivedChain(headers);
        let previousDate = null;

        // Calculate Latency & Build Hops
        report.modules.infrastructure.data.hops = hops.map((hop, i) => {
            let delay = 0;
            if (hop.date && previousDate) {
                delay = this._calcDelay(hop.date, previousDate);
            }
            if (i > 0) previousDate = hop.date;
            else previousDate = hop.date; // Init

            if (delay > 600) { // 10 mins
                report.modules.infrastructure.issues.push({ level: 'Medium', msg: `High Latency at hop ${i + 1}: ${delay}s` });
            }

            return { ...hop, delay: delay, number: i + 1 };
        });

        // Determine Origin IP (Module 2)
        const originHop = hops[0];
        if (originHop && originHop.ip) {
            report.modules.infrastructure.data.originIp = originHop.ip;
        } else {
            report.modules.infrastructure.issues.push({ level: 'Low', msg: "Could not decisively identify Origin IP." });
        }

        // --- MODULE 4: Content & Payload ---
        const contentType = headers['content-type'] || '';
        report.modules.content.data.mime = contentType;

        if (contentType.includes('multipart/mixed')) {
            report.modules.content.data.hasAttachments = true;
        }

        // Encoding check
        const encoding = headers['content-transfer-encoding'] || '';
        if (encoding === 'base64' || encoding === 'quoted-printable') {
            report.modules.content.data.encoding = encoding;
        }

        // --- MODULE 5: Vendor Specifics ---
        if (headers['x-forefront-antispam-report']) {
            report.modules.vendor.data.microsoft = headers['x-forefront-antispam-report'];
            if (headers['x-forefront-antispam-report'].includes('SCL:9')) {
                report.riskScore -= 50;
                report.modules.vendor.issues.push({ level: 'Critical', msg: 'Microsoft SCL=9 (High Confidence Spam)' });
            }
        }
        if (headers['x-google-dkim-signature']) report.modules.vendor.data.google = 'Present';
        if (headers['x-proofpoint-spam-details']) report.modules.vendor.data.proofpoint = 'Present';

        return report;
    }

    // Stage 2: Enrichment (Threat Intel)
    async enrichReport(report) {
        // --- MODULE 3: Threat Intelligence (Async) ---
        // 1. IP Reputation
        const originIp = report.modules.infrastructure.data.originIp;
        if (originIp) {
            const rep = await this.reputation.checkIP(originIp);
            report.modules.threatIntel.data.originReputation = rep;

            // Analyze Rep
            if (rep.vt.status === 'analyzed' && rep.vt.data.malicious > 0) {
                report.riskScore -= (rep.vt.data.malicious * 5); // -5 per vendor
                report.modules.threatIntel.issues.push({ level: 'Critical', msg: `Origin IP flagged by ${rep.vt.data.malicious} vendors.` });
                report.riskScore -= 15; // Specific penalty requested
            }

            // ASN Context
            if (rep.isp && (rep.isp.includes('Google') || rep.isp.includes('Amazon'))) {
                // report.modules.threatIntel.issues.push({ level: 'Info', msg: 'Origin is a major cloud provider.' });
            }
        }

        // 2. Domain Reputation & Age
        const from = report.rawHeaders['from'] || '';
        const domain = from.match(/@([^>]+)/)?.[1];
        if (domain) {
            const domRep = await this._getDomainProfile(domain);
            report.modules.threatIntel.data.senderDomain = domRep;

            if (domRep.dns.a.length === 0) {
                report.riskScore -= 10;
                report.modules.threatIntel.issues.push({ level: 'High', msg: `Sender Domain ${domain} has no A records (Unresolvable).` });
            }

            // Check Age
            if (domRep.ageDays !== null && domRep.ageDays < 7) {
                report.riskScore -= 10;
                report.modules.threatIntel.issues.push({ level: 'High', msg: `Domain is less than 1 week old (${domRep.ageDays} days).` });
            } else if (domRep.ageDays !== null && domRep.ageDays < 30) {
                report.riskScore -= 5;
                report.modules.threatIntel.issues.push({ level: 'Medium', msg: `Domain is less than 30 days old.` });
            }
        }

        // Final Score Clamp
        report.riskScore = Math.max(0, Math.min(100, report.riskScore));
        report.summary = this.generateSummary(report.riskScore);
        return report;
    }

    async _getDomainProfile(domain) {
        const profile = { domain: domain, dns: {}, reputation: null, ageDays: null };

        // DNS
        const [a, mx, txt] = await Promise.all([
            this.lookupDNS(domain, 'A'),
            this.lookupDNS(domain, 'MX'),
            this.lookupDNS(domain, 'TXT')
        ]);

        profile.dns.a = a?.Answer?.map(x => x.data) || [];
        profile.dns.mx = mx?.Answer?.map(x => x.data) || [];
        profile.dns.spf = txt?.Answer?.find(x => x.data.includes('v=spf1'))?.data || null;

        // Rep & Age via VT
        const rep = await this.reputation.checkDomain(domain);
        profile.reputation = rep;

        if (rep.vt.status === 'analyzed' && rep.vt.data.creation_date) {
            const created = rep.vt.data.creation_date; // unix timestamp
            const diffTime = Math.abs(Date.now() / 1000 - created);
            profile.ageDays = Math.ceil(diffTime / (60 * 60 * 24));
        }

        return profile;
    }

    generateSummary(score) {
        if (score < 50) return "CRITICAL RISK: Multiple high-severity indicators detected (Spoofing, Blacklisted IP, or New Domain). Block immediately.";
        if (score < 80) return "SUSPICIOUS: Identifying markers exist but aren't conclusive. Verify Sender identity manually.";
        return "CLEAN: Email passed aligned authentication and reputation checks.";
    }

    // --- DETAILED FORENSIC MODULES ---

    // 1. IP Analysis (Forensic 360)
    async analyzeIPs(ips) {
        const results = [];
        for (const ip of ips) {
            if (!ip.trim()) continue;

            // 1. Parallel Lookups
            const [ptrRes, rep] = await Promise.all([
                this._lookupPTR(ip.trim()),
                this.reputation.checkIP(ip.trim())
            ]);

            // 2. Synthesize Data
            const analysis = {
                type: 'IP',
                value: ip.trim(),
                identity: {
                    version: ip.includes(':') ? 'IPv6' : 'IPv4',
                    isp: rep.isp || 'Unknown',
                    asn: rep.asn || 'Unknown',
                    ptr: ptrRes || 'No PTR Record'
                },
                geo: {
                    country: rep.country || 'Unknown',
                    usage: rep.abuse.data?.usageType || 'Unknown' // e.g. Data Center, Residential
                },
                risk: {
                    score: 0,
                    level: 'Green', // Green, Yellow, Red
                    flags: [],
                    blacklist: rep.vt.data?.malicious > 0 ? `Listed on ${rep.vt.data.malicious} blocklists` : 'Clean',
                    abuseScore: rep.abuse.data?.score || 0
                }
            };

            // 3. Risk Logic (Traffic Light)
            // Baseline deduction
            if (analysis.risk.abuseScore > 0) analysis.risk.score += analysis.risk.abuseScore;
            if (rep.vt.data?.malicious > 0) analysis.risk.score += (rep.vt.data.malicious * 10);

            // Usage Type Analysis
            const usage = (analysis.geo.usage || '').toLowerCase();
            if (usage.includes('business') || usage.includes('data center')) {
                analysis.risk.flags.push('Data Center/Business IP (Potential Bot/VPN)');
                analysis.risk.score += 20;
            } else if (usage.includes('residential')) {
                analysis.risk.flags.push('Residential IP (Likely User Device)');
            }

            // Thresholds
            if (analysis.risk.score >= 50 || rep.vt.data?.malicious > 0) {
                analysis.risk.level = 'Red';
            } else if (analysis.risk.score >= 20 || usage.includes('vpn')) {
                analysis.risk.level = 'Yellow';
            }

            analysis.data = rep; // Keep raw data
            results.push(analysis);
        }
        return results;
    }

    // 2. Domain Analysis (Identity & Trust)
    async analyzeDomains(domains) {
        const results = [];
        const protectedBrands = ['google', 'microsoft', 'paypal', 'apple', 'amazon', 'facebook', 'netflix', 'bank'];

        for (const d of domains) {
            if (!d.trim()) continue;

            // 1. Recon
            const profile = await this._getDomainProfile(d.trim());

            // Additional recon for standalone mode
            const [ns, aaaa, dmarc] = await Promise.all([
                this.lookupDNS(d.trim(), 'NS'),
                this.lookupDNS(d.trim(), 'AAAA'),
                this.lookupDNS(`_dmarc.${d.trim()}`, 'TXT')
            ]);

            profile.dns.ns = ns?.Answer?.map(x => x.data) || [];
            profile.dns.aaaa = aaaa?.Answer?.map(x => x.data) || [];
            if (dmarc?.Answer) profile.dns.dmarc = dmarc.Answer.map(x => x.data).join(' ');

            // 2. Analysis Construction
            const analysis = {
                type: 'Domain',
                value: d.trim(),
                identity: {
                    registrar: profile.reputation.vt.data?.registrar || 'Unknown',
                    ageDays: profile.ageDays,
                    created: profile.reputation.vt.data?.creation_date ? new Date(profile.reputation.vt.data.creation_date * 1000).toLocaleDateString() : 'Unknown'
                },
                dns: profile.dns,
                risk: {
                    level: 'Green',
                    flags: [],
                    typosquat: false
                },
                content: {
                    category: profile.reputation.vt.data?.categories ? Object.values(profile.reputation.vt.data.categories)[0] : 'Uncategorized'
                }
            };

            // 3. Risk Logic
            // Age
            if (analysis.identity.ageDays !== null) {
                if (analysis.identity.ageDays < 7) {
                    analysis.risk.level = 'Red';
                    analysis.risk.flags.push(`New Domain (< 7 days): ${analysis.identity.ageDays} days old`);
                } else if (analysis.identity.ageDays < 30) {
                    if (analysis.risk.level !== 'Red') analysis.risk.level = 'Yellow';
                    analysis.risk.flags.push(`Young Domain (< 30 days)`);
                }
            } else {
                analysis.risk.flags.push('Age Unknown (Caution)');
            }

            // Auth
            if (!analysis.dns.mx.length) {
                analysis.risk.flags.push('No MX Records (Cannot receive email)');
                if (analysis.risk.level !== 'Red') analysis.risk.level = 'Yellow';
            }
            if (!analysis.dns.dmarc) {
                analysis.risk.flags.push('Missing DMARC Policy');
                if (analysis.risk.level !== 'Red') analysis.risk.level = 'Yellow';
            }

            // Typosquatting
            const domainBase = d.split('.')[0].toLowerCase();
            protectedBrands.forEach(brand => {
                if (domainBase !== brand && (domainBase.includes(brand) || this._isFuzzyMatch(domainBase, brand))) {
                    analysis.risk.typosquat = true;
                    analysis.risk.flags.push(`Possible Typosquatting of '${brand}'`);
                    analysis.risk.level = 'Red';
                }
            });

            // Rep
            if (profile.reputation.vt.data?.malicious > 0) {
                analysis.risk.level = 'Red';
                analysis.risk.flags.push(`Flagged by ${profile.reputation.vt.data.malicious} vendors`);
            }

            if (analysis.content.category === 'Uncategorized') {
                analysis.risk.flags.push('Uncategorized Content');
                if (analysis.risk.level === 'Green') analysis.risk.level = 'Yellow';
            }

            analysis.data = profile;
            results.push(analysis);
        }
        return results;
    }

    async _lookupPTR(ip) {
        try {
            // Reverse IP: 1.2.3.4 -> 4.3.2.1.in-addr.arpa
            const parts = ip.split('.');
            if (parts.length === 4) { // IPv4
                const reversed = parts.reverse().join('.') + '.in-addr.arpa';
                const res = await this.lookupDNS(reversed, 'PTR');
                return res?.Answer?.[0]?.data || null;
            }
            return null; // IPv6 TODO
        } catch { return null; }
    }

    _isFuzzyMatch(s1, s2) {
        const norm1 = s1.replace(/0/g, 'o').replace(/1/g, 'l');
        const norm2 = s2.replace(/0/g, 'o').replace(/1/g, 'l');
        return norm1 === norm2;
    }
}
