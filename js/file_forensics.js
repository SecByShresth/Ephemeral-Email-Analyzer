// --- UNIVERSAL FORENSIC FILE ENGINE (Client-Side) ---
class FileForensics {
    constructor() {
        // "YARA-Lite" Rule Definitions (Regex-based)
        this.yaraRules = [
            // PDF Rules
            { name: 'PDF_Embedded_JS', type: 'pdf', pattern: /\/JavaScript/i, level: 'High', tag: 'Exploit' },
            { name: 'PDF_OpenAction', type: 'pdf', pattern: /\/OpenAction/i, level: 'Medium', tag: 'Behavior' },
            { name: 'PDF_Launch_Cmd', type: 'pdf', pattern: /\/Launch/i, level: 'High', tag: 'Dropper' },
            { name: 'PDF_URI_Link', type: 'pdf', pattern: /\/URI/i, level: 'Low', tag: 'Phishing' },

            // Office Rules
            { name: 'Office_VBA_Macro', type: 'office', pattern: /vbaProject\.bin/i, level: 'High', tag: 'Macro' },
            { name: 'Office_AutoExec', type: 'office', pattern: /AutoOpen|AutoExec/i, level: 'High', tag: 'Persistence' },
            { name: 'Office_PowerShell', type: 'office', pattern: /powershell\.exe/i, level: 'Critical', tag: 'Execution' },
            { name: 'Office_Suspicious_URL', type: 'office', pattern: /http[s]?:\/\//i, level: 'Medium', tag: 'IoC' },

            // PE/Exe Rules
            { name: 'PE_Suspicious_Import_VirtualAlloc', type: 'exe', pattern: /VirtualAlloc/i, level: 'Medium', tag: 'Unpacking' },
            { name: 'PE_Suspicious_Import_ShellExec', type: 'exe', pattern: /ShellExecute/i, level: 'High', tag: 'Execution' },
            { name: 'PE_Web_Request', type: 'exe', pattern: /InternetOpen|URLDownloadToFile/i, level: 'High', tag: 'Downloader' },
            { name: 'PE_Reflective_Injection', type: 'exe', pattern: /ReflectiveLoader/i, level: 'Critical', tag: 'Advanced' }
        ];
    }

    async analyze(file) {
        const buffer = await file.arrayBuffer();
        const bytes = new Uint8Array(buffer);
        const decoder = new TextDecoder('utf-8');
        // Safe string conversion (limit to 2MB for patterns)
        const textContent = decoder.decode(bytes.slice(0, 2000000)).replace(/[^\x20-\x7E]/g, ' ');

        // 1. Magic Byte Identification
        const typeInfo = this.identifyType(bytes); // { type: 'pdf', magic: '2550', name: 'PDF Document' }

        // 2. Extension Consistency
        const ext = file.name.split('.').pop().toLowerCase();
        let mismatch = false;
        if (typeInfo.exts && !typeInfo.exts.includes(ext)) mismatch = true;
        // Office/Zip exception
        if (typeInfo.type === 'zip' && ['docx', 'xlsx', 'pptx'].includes(ext)) mismatch = false;

        // 3. Cryptographic Hashing
        const sha256 = await this.calculateHash(buffer);

        // 4. Entropy
        const entropy = this.calculateEntropy(bytes);

        // 5. YARA-Lite Scan
        const yaraHits = this.scanYara(textContent, typeInfo.type);

        // 6. String Extraction (High Value)
        const strings = this.extractStrings(textContent);

        // 7. Risk Scoring
        let riskScore = 0;
        let findings = [];

        if (mismatch) {
            riskScore += 50;
            findings.push(`FATAL: Type Mismatch (Real: ${typeInfo.name}, Ext: .${ext})`);
        }
        if (entropy > 7.2) {
            riskScore += 20;
            findings.push('High Entropy (Likely Packed/Encrypted)');
        }

        yaraHits.forEach(hit => {
            if (hit.level === 'Critical') riskScore += 50;
            if (hit.level === 'High') riskScore += 30;
            if (hit.level === 'Medium') riskScore += 10;
        });

        // String Risks
        if (strings.urls.length > 0) riskScore += (strings.urls.length * 2);
        if (strings.commands.length > 0) {
            riskScore += 20;
            findings.push(`Compromise Indicators: ${strings.commands.join(', ')}`);
        }

        const riskLevel = riskScore >= 50 ? 'Red' : (riskScore >= 20 ? 'Yellow' : 'Green');

        return {
            meta: {
                filename: file.name,
                size: (file.size / 1024).toFixed(2) + ' KB',
                sha256: sha256
            },
            type: {
                real: typeInfo.name,
                magic: typeInfo.magic,
                matchesExtension: !mismatch
            },
            forensics: {
                entropy: entropy,
                yara: yaraHits,
                strings: strings
            },
            risk: {
                score: riskScore,
                level: riskLevel,
                flags: findings
            }
        };
    }

    identifyType(bytes) {
        const hex = Array.from(bytes.slice(0, 4)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

        if (hex.startsWith('4D5A')) return { type: 'exe', name: 'Windows Executable (PE)', magic: 'MZ', exts: ['exe', 'dll', 'sys'] };
        if (hex.startsWith('25504446')) return { type: 'pdf', name: 'PDF Document', magic: '%PDF', exts: ['pdf'] };
        if (hex.startsWith('504B0304')) return { type: 'zip', name: 'ZIP Archive / Office XML', magic: 'PK..', exts: ['zip', 'jar', 'docx', 'xlsx', 'pptx'] };
        if (hex.startsWith('D0CF11E0')) return { type: 'office', name: 'Legacy Office / OLE', magic: 'D0CF', exts: ['doc', 'xls', 'ppt', 'msg'] };

        return { type: 'unknown', name: 'Unknown Binary', magic: hex, exts: [] };
    }

    scanYara(text, fileType) {
        const hits = [];
        // Scan general + specific rules
        const relevantRules = this.yaraRules.filter(r => r.type === fileType || r.type === 'global');

        relevantRules.forEach(rule => {
            if (rule.pattern.test(text)) {
                hits.push({
                    rule: rule.name,
                    level: rule.level,
                    tag: rule.tag
                });
            }
        });

        // Use patterns for zip/office too if it's an XML format
        if (fileType === 'zip') {
            const officeRules = this.yaraRules.filter(r => r.type === 'office');
            officeRules.forEach(rule => {
                if (rule.pattern.test(text)) hits.push({ rule: rule.name, level: rule.level, tag: rule.tag });
            });
        }

        return hits;
    }

    extractStrings(text) {
        const results = {
            urls: [],
            ips: [],
            emails: [],
            commands: []
        };

        // Regex Patterns
        const urlRegex = /https?:\/\/[a-zA-Z0-9\-\.]+(\.[a-zA-Z]{2,})?(:[0-9]{1,5})?(\/[\S]*)?/gi;
        const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
        const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
        const cmdRegex = /(powershell|cmd\.exe|wget|curl|bitsadmin|certutil|rundll32|regsvr32)/gi;

        // Extraction limit to avoid massive arrays
        const rawUrls = text.match(urlRegex) || [];
        results.urls = [...new Set(rawUrls)].slice(0, 10); // Top 10 unique

        const rawIps = text.match(ipRegex) || [];
        results.ips = [...new Set(rawIps)].filter(ip => !ip.startsWith('0.')).slice(0, 10);

        const rawEmails = text.match(emailRegex) || [];
        results.emails = [...new Set(rawEmails)].slice(0, 10);

        const rawCmds = text.match(cmdRegex) || [];
        results.commands = [...new Set(rawCmds)].map(c => c.toLowerCase());

        return results;
    }

    calculateEntropy(bytes) {
        const freq = {};
        for (let b of bytes) freq[b] = (freq[b] || 0) + 1;
        let e = 0;
        for (let i = 0; i < 256; i++) {
            if (freq[i]) {
                const p = freq[i] / bytes.length;
                e -= p * Math.log2(p);
            }
        }
        return parseFloat(e.toFixed(2));
    }

    async calculateHash(buffer) {
        const digest = await crypto.subtle.digest('SHA-256', buffer);
        return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
    }
}
