class EmailParser {
    static parseHeaders(rawText) {
        const lines = rawText.split(/\r?\n/);
        const headers = {};
        let currentKey = null;

        lines.forEach(line => {
            if (line.match(/^\s/) && currentKey) {
                // Continued line
                headers[currentKey] += " " + line.trim();
            } else {
                const match = line.match(/^([\w-]+):\s*(.*)$/);
                if (match) {
                    currentKey = match[1].toLowerCase();
                    const value = match[2].trim();
                    if (headers[currentKey]) {
                        if (Array.isArray(headers[currentKey])) {
                            headers[currentKey].push(value);
                        } else {
                            headers[currentKey] = [headers[currentKey], value];
                        }
                    } else {
                        headers[currentKey] = value;
                    }
                }
            }
        });

        return headers;
    }

    static extractReceivedChain(headers) {
        let received = headers['received'] || [];
        if (!Array.isArray(received)) received = [received];
        
        return received.map(line => {
            // Simple extraction: from [ip/host] by [host] with [proto] id [id]
            const fromMatch = line.match(/from\s+([^\s]+)/i);
            const byMatch = line.match(/by\s+([^\s]+)/i);
            const withMatch = line.match(/with\s+([^\s]+)/i);
            const idMatch = line.match(/id\s+([^\s]+)/i);
            const forMatch = line.match(/for\s+([^\s]+)/i);
            const dateMatch = line.match(/;\s*(.+)$/);

            // Extract IP from "from" part
            const ipMatch = line.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);

            return {
                raw: line,
                from: fromMatch ? fromMatch[1] : null,
                by: byMatch ? byMatch[1] : null,
                with: withMatch ? withMatch[1] : null,
                id: idMatch ? idMatch[1] : null,
                for: forMatch ? forMatch[1] : null,
                ip: ipMatch ? ipMatch[1] : null,
                date: dateMatch ? new Date(dateMatch[1]) : null,
                dateRaw: dateMatch ? dateMatch[1] : null
            };
        });
    }

    static extractAuthResults(headers) {
        const authResults = headers['authentication-results'] || [];
        const results = Array.isArray(authResults) ? authResults : [authResults];
        
        const extracted = {
            spf: null,
            dkim: [],
            dmarc: null
        };

        results.forEach(res => {
            const spfMatch = res.match(/spf=([^\s;]+)/i);
            if (spfMatch) extracted.spf = spfMatch[1];

            const dkimMatches = res.matchAll(/dkim=([^\s;]+)/ig);
            for (const match of dkimMatches) {
                extracted.dkim.push(match[1]);
            }

            const dmarcMatch = res.match(/dmarc=([^\s;]+)/i);
            if (dmarcMatch) extracted.dmarc = dmarcMatch[1];
        });

        return extracted;
    }
}
