class EmailParser {
    static parseHeaders(rawText) {
        // Unfold headers first (RFC 5322)
        // 1. Remove carriage returns, keep newlines
        // 2. Unfold: newline + whitespace -> space
        const unfolded = rawText
            .replace(/\r\n/g, '\n')
            .replace(/\n\s+/g, ' ');

        const lines = unfolded.split('\n');
        const headers = {};

        lines.forEach(line => {
            // MATCH: "Key: Value" (forgiving leading whitespace)
            const match = line.match(/^\s*([\w-]+):\s*(.*)$/);
            if (match) {
                const key = match[1].toLowerCase();
                const value = match[2].trim();

                if (headers[key]) {
                    if (Array.isArray(headers[key])) {
                        headers[key].push(value);
                    } else {
                        headers[key] = [headers[key], value];
                    }
                } else {
                    headers[key] = value;
                }
            }
        });

        return headers;
    }

    static extractReceivedChain(headers) {
        let received = headers['received'] || [];
        if (!Array.isArray(received)) received = [received];

        // Process in reverse (Bottom-up = Origin -> Recipient)
        // Standard headers: Top = Recipient (Last Hop), Bottom = Origin (First Hop)
        // .reverse() puts Origin at index 0.

        return received.map(line => {
            // Robust IP Regex: Matches [1.2.3.4], 1.2.3.4, ipv6:...
            // We prioritize brackets but fall back to loose IPs if needed.
            let ip = null;

            // Try standard bracketed IP first (most reliable)
            const bracketMatch = line.match(/(?:\[|ipv6:)\s*([0-9a-f:.]+)\s*(?:\]| )/i);
            if (bracketMatch) {
                ip = bracketMatch[1];
            } else {
                // Fallback: loose IPv4 (risky but needed if brackets missing)
                // Avoid matching version numbers like 2.5.1
                const looseMatch = line.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
                if (looseMatch) ip = looseMatch[1];
            }

            // Extract 'by' and 'from' (hostnames)
            const fromMatch = line.match(/from\s+([^\s;]+)/i);
            const byMatch = line.match(/by\s+([^\s;]+)/i);
            const dateMatch = line.match(/;\s*(.+)$/);

            return {
                raw: line,
                from: fromMatch ? fromMatch[1] : 'Unknown',
                by: byMatch ? byMatch[1] : 'Unknown',
                ip: ip,
                date: dateMatch ? dateMatch[1] : null
            };
        }).reverse();
    }

    static extractAuthResults(headers) {
        const authResults = headers['authentication-results'] || [];
        const results = Array.isArray(authResults) ? authResults : [authResults];

        const extracted = { spf: null, dkim: [], dmarc: null };

        results.forEach(res => {
            if (!res) return;
            // SPF
            const spfMatch = res.match(/spf=([a-z]+)/i);
            if (spfMatch && !extracted.spf) extracted.spf = spfMatch[1].toLowerCase();

            // DKIM (Global pass/fail)
            if (res.includes('dkim=pass')) extracted.dkim.push('pass');
            else if (res.includes('dkim=fail')) extracted.dkim.push('fail');

            // DMARC
            const dmarcMatch = res.match(/dmarc=([a-z]+)/i);
            if (dmarcMatch && !extracted.dmarc) extracted.dmarc = dmarcMatch[1].toLowerCase();
        });

        // Fallback: Received-SPF header
        if (!extracted.spf && headers['received-spf']) {
            extracted.spf = headers['received-spf'].split(' ')[0].toLowerCase();
        }

        return extracted;
    }
}
