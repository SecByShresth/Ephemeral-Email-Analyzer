class ReputationProvider {
    constructor() {
        this.vtKey = localStorage.getItem('vt_key') || '';
        this.abuseKey = localStorage.getItem('abuse_key') || '';
    }

    setKeys(vt, abuse) {
        this.vtKey = vt;
        this.abuseKey = abuse;
        localStorage.setItem('vt_key', vt);
        localStorage.setItem('abuse_key', abuse);
    }

    async checkIP(ip) {
        const results = {
            vt: null,
            abuse: null,
            asn: 'Unknown',
            isp: 'Unknown'
        };

        if (this.vtKey) {
            try {
                const response = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
                    headers: { 'x-apikey': this.vtKey }
                });
                if (response.ok) {
                    const data = await response.json();
                    results.vt = {
                        malicious: data.data.attributes.last_analysis_stats.malicious,
                        suspicious: data.data.attributes.last_analysis_stats.suspicious,
                        asn: data.data.attributes.asn,
                        as_owner: data.data.attributes.as_owner
                    };
                    results.asn = data.data.attributes.as_owner || results.asn;
                }
            } catch (e) { console.error('VT IP check failed', e); }
        }

        if (this.abuseKey) {
            try {
                const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`, {
                    headers: { 'Key': this.abuseKey, 'Accept': 'application/json' }
                });
                if (response.ok) {
                    const data = await response.json();
                    results.abuse = {
                        score: data.data.abuseConfidenceScore,
                        usageType: data.data.usageType,
                        isp: data.data.isp
                    };
                    results.isp = data.data.isp || results.isp;
                }
            } catch (e) { console.error('AbuseIPDB check failed', e); }
        }

        // Add a small delay to avoid rate limits if multiple IPs
        await new Promise(r => setTimeout(r, 200));

        return results;
    }

    async checkDomain(domain) {
        const results = {
            vt: null,
            whois: null
        };

        if (this.vtKey) {
            try {
                const response = await fetch(`https://www.virustotal.com/api/v3/domains/${domain}`, {
                    headers: { 'x-apikey': this.vtKey }
                });
                if (response.ok) {
                    const data = await response.json();
                    results.vt = {
                        malicious: data.data.attributes.last_analysis_stats.malicious,
                        suspicious: data.data.attributes.last_analysis_stats.suspicious,
                        categories: data.data.attributes.categories
                    };
                }
            } catch (e) { console.error('VT Domain check failed', e); }
        }

        return results;
    }

    async checkHash(hash) {
        if (!this.vtKey) return null;
        try {
            const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
                headers: { 'x-apikey': this.vtKey }
            });
            if (response.ok) {
                const data = await response.json();
                return {
                    malicious: data.data.attributes.last_analysis_stats.malicious,
                    suspicious: data.data.attributes.last_analysis_stats.suspicious,
                    type: data.data.attributes.type_description
                };
            }
        } catch (e) { console.error('VT Hash check failed', e); }
        return null;
    }
}
