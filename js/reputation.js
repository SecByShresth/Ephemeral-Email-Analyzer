class ReputationProvider {
    constructor() {
        this.vtKey = '';
        this.abuseKey = '';
        this.timeout = 5000; // 5 seconds timeout
    }

    setKeys(vt, abuse) {
        this.vtKey = vt;
        this.abuseKey = abuse;
    }

    async _fetchWithTimeout(url, options) {
        const controller = new AbortController();
        const id = setTimeout(() => controller.abort(), this.timeout);
        try {
            const response = await fetch(url, { ...options, signal: controller.signal });
            clearTimeout(id);
            return response;
        } catch (e) {
            clearTimeout(id);
            throw e;
        }
    }

    async checkIP(ip) {
        const results = {
            vt: { status: 'n/a', data: null },
            abuse: { status: 'n/a', data: null },
            asn: 'Unknown',
            isp: 'Unknown',
            country: 'Unknown'
        };

        const checks = [];

        // VirusTotal
        if (this.vtKey) {
            checks.push(
                this._fetchWithTimeout(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
                    headers: { 'x-apikey': this.vtKey }
                })
                    .then(async res => {
                        if (res.ok) {
                            const data = await res.json();
                            results.vt.status = 'analyzed';
                            results.vt.data = {
                                malicious: data.data.attributes.last_analysis_stats.malicious,
                                suspicious: data.data.attributes.last_analysis_stats.suspicious,
                                asn: data.data.attributes.asn,
                                as_owner: data.data.attributes.as_owner,
                                country: data.data.attributes.country
                            };
                            // Enrich shared fields
                            if (results.asn === 'Unknown') results.asn = results.vt.data.as_owner;
                            if (results.country === 'Unknown') results.country = results.vt.data.country;
                        } else {
                            results.vt.status = 'error';
                        }
                    })
                    .catch(() => { results.vt.status = 'timeout'; })
            );
        } else {
            results.vt.status = 'no_key';
        }

        // AbuseIPDB
        if (this.abuseKey) {
            checks.push(
                this._fetchWithTimeout(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`, {
                    headers: { 'Key': this.abuseKey, 'Accept': 'application/json' }
                })
                    .then(async res => {
                        if (res.ok) {
                            const data = await res.json();
                            results.abuse.status = 'analyzed';
                            results.abuse.data = {
                                score: data.data.abuseConfidenceScore,
                                usageType: data.data.usageType,
                                isp: data.data.isp,
                                countryCode: data.data.countryCode
                            };
                            // Enrich shared fields
                            if (results.isp === 'Unknown') results.isp = results.abuse.data.isp;
                            if (results.country === 'Unknown') results.country = results.abuse.data.countryCode;
                        } else {
                            results.abuse.status = 'error';
                        }
                    })
                    .catch(() => { results.abuse.status = 'timeout'; })
            );
        } else {
            results.abuse.status = 'no_key';
        }

        await Promise.allSettled(checks);
        return results;
    }

    async checkDomain(domain) {
        const results = { vt: { status: 'n/a', data: null } };

        if (this.vtKey) {
            try {
                const res = await this._fetchWithTimeout(`https://www.virustotal.com/api/v3/domains/${domain}`, {
                    headers: { 'x-apikey': this.vtKey }
                });
                if (res.ok) {
                    const data = await res.json();
                    results.vt.status = 'analyzed';
                    results.vt.data = {
                        malicious: data.data.attributes.last_analysis_stats.malicious,
                        creation_date: data.data.attributes.creation_date,
                        registrar: data.data.attributes.registrar
                    };
                } else {
                    results.vt.status = 'error';
                }
            } catch (error) {
                results.vt.status = 'timeout';
            }
        } else {
            results.vt.status = 'no_key';
        }
        return results;
    }

    async checkHash(hash) {
        if (!this.vtKey) return { status: 'no_key', data: null };
        try {
            const res = await this._fetchWithTimeout(`https://www.virustotal.com/api/v3/files/${hash}`, {
                headers: { 'x-apikey': this.vtKey }
            });
            if (res.ok) {
                const data = await res.json();
                return {
                    status: 'analyzed',
                    data: {
                        malicious: data.data.attributes.last_analysis_stats.malicious,
                        type: data.data.attributes.type_description,
                        first_submission_date: data.data.attributes.first_submission_date
                    }
                };
            }
            return { status: 'error', data: null };
        } catch (error) {
            return { status: 'timeout', data: null };
        }
    }
}
