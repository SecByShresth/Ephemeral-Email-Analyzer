"""
Ephemeral Email Header & Attachment Analysis Tool - Backend
FastAPI server with in-memory TTL cache for security analysis
"""

import asyncio
import json
import logging
import os
import tempfile
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
import re
import ipaddress

import dns.resolver
import magic
import requests
import whois
import yara
from cachetools import TTLCache
from fastapi import FastAPI, File, Form, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import email
from email.message import EmailMessage
import base64
import hashlib
import socket

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment variables
ABUSEIPDB_API_KEY = "ABUSEIPDB API"
VIRUSTOTAL_API_KEY = "VIRUS TOTAL API"
HYBRID_ANALYSIS_API_KEY = "Hybrid Analysis API"

# TTL Cache - 15 minutes
TTL_SECONDS = 15 * 60
cache = TTLCache(maxsize=1000, ttl=TTL_SECONDS)

# WebSocket connections
websocket_connections: Dict[str, WebSocket] = {}

# FastAPI app
app = FastAPI(title="Ephemeral Email Analysis Tool", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models
class AnalysisRequest(BaseModel):
    headers: Optional[str] = None
    urls: Optional[List[str]] = None

class AnalysisResult(BaseModel):
    analysis_id: str
    status: str
    findings: Dict[str, Any] = Field(default_factory=dict)
    logs: List[str] = Field(default_factory=list)
    created_at: datetime
    summary: Dict[str, Any] = Field(default_factory=dict)

class LogEntry(BaseModel):
    timestamp: datetime
    message: str
    level: str = "INFO"

# YARA rules for common malware patterns
YARA_RULES = """
rule SuspiciousPE {
    meta:
        description = "Suspicious PE file characteristics"
    strings:
        $mz = { 4D 5A }
        $pe = "PE"
    condition:
        $mz at 0 and $pe
}

rule MacroEnabled {
    meta:
        description = "Office document with macros"
    strings:
        $vba = "vbaProject"
        $macro = "macros"
    condition:
        any of them
}

rule SuspiciousScript {
    meta:
        description = "Suspicious script patterns"
    strings:
        $ps1 = "powershell" nocase
        $cmd1 = "cmd.exe" nocase
        $eval = "eval(" nocase
        $exec = "exec(" nocase
    condition:
        any of them
}
"""

try:
    yara_rules = yara.compile(source=YARA_RULES)
except Exception as e:
    logger.warning(f"Failed to compile YARA rules: {e}")
    yara_rules = None

# Helper functions
async def send_log_update(analysis_id: str, message: str, level: str = "INFO"):
    """Send real-time log update via WebSocket"""
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "message": message,
        "level": level
    }

    if analysis_id in cache:
        cache[analysis_id]["logs"].append(log_entry)

    if analysis_id in websocket_connections:
        try:
            await websocket_connections[analysis_id].send_text(json.dumps(log_entry))
        except Exception as e:
            logger.warning(f"Failed to send WebSocket message: {e}")

def get_file_hash(file_content: bytes) -> Dict[str, str]:
    return {
        "md5": hashlib.md5(file_content).hexdigest(),
        "sha1": hashlib.sha1(file_content).hexdigest(),
        "sha256": hashlib.sha256(file_content).hexdigest()
    }

def normalize_url(url: str) -> str:
    """Normalize URL by adding scheme if missing"""
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        # Try HTTPS first for security
        url = 'https://' + url
    return url

def is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IP address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_private_ip(ip: str) -> bool:
    """Check if IP is private/internal"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

# ---------------- IP Analysis ----------------
async def analyze_ip_address(analysis_id: str, ip: str) -> Dict[str, Any]:
    """Analyze IP address for reputation and geolocation"""
    result = {"ip": ip, "findings": {}}

    try:
        await send_log_update(analysis_id, f"Analyzing IP: {ip}")

        # Skip private IPs
        if is_private_ip(ip):
            result["findings"]["status"] = "private_ip"
            return result

        # AbuseIPDB check
        if ABUSEIPDB_API_KEY:
            await send_log_update(analysis_id, f"Checking AbuseIPDB for {ip}")
            headers = {
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            }

            try:
                response = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                    headers=headers,
                    timeout=10
                )

                if response.status_code == 200:
                    abuse_data = response.json()
                    result["findings"]["abuseipdb"] = {
                        "abuse_confidence": abuse_data.get("data", {}).get("abuseConfidencePercentage", 0),
                        "is_public": abuse_data.get("data", {}).get("isPublic", False),
                        "usage_type": abuse_data.get("data", {}).get("usageType", "unknown"),
                        "country_code": abuse_data.get("data", {}).get("countryCode", "unknown"),
                        "total_reports": abuse_data.get("data", {}).get("totalReports", 0)
                    }
                else:
                    await send_log_update(analysis_id, f"AbuseIPDB check failed: {response.status_code}", "WARNING")
            except Exception as e:
                await send_log_update(analysis_id, f"AbuseIPDB check error: {str(e)}", "WARNING")

        # VirusTotal IP check
        if VIRUSTOTAL_API_KEY:
            await send_log_update(analysis_id, f"Checking VirusTotal for IP {ip}")
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}

            try:
                vt_response = requests.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers=headers,
                    timeout=10
                )

                if vt_response.status_code == 200:
                    vt_data = vt_response.json()
                    stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    result["findings"]["virustotal"] = {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "clean": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                        "country": vt_data.get("data", {}).get("attributes", {}).get("country", "unknown"),
                        "asn": vt_data.get("data", {}).get("attributes", {}).get("asn", 0),
                        "as_owner": vt_data.get("data", {}).get("attributes", {}).get("as_owner", "unknown")
                    }
                else:
                    await send_log_update(analysis_id, f"VirusTotal IP check failed: {vt_response.status_code}", "WARNING")
            except Exception as e:
                await send_log_update(analysis_id, f"VirusTotal IP check error: {str(e)}", "WARNING")

    except Exception as e:
        logger.error(f"IP analysis failed for {ip}: {e}")
        result["error"] = str(e)
        await send_log_update(analysis_id, f"IP analysis error for {ip}: {str(e)}", "ERROR")

    return result

# ---------------- Domain Analysis ----------------
async def analyze_domain(analysis_id: str, domain: str) -> Dict[str, Any]:
    """Analyze domain for reputation, WHOIS, and DNS info"""
    result = {"domain": domain, "findings": {}}

    try:
        await send_log_update(analysis_id, f"Analyzing domain: {domain}")

        # WHOIS lookup
        try:
            await send_log_update(analysis_id, f"Performing WHOIS lookup for {domain}")
            w = whois.whois(domain)
            if w:
                result["findings"]["whois"] = {
                    "creation_date": str(w.creation_date) if w.creation_date else None,
                    "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                    "registrar": w.registrar if hasattr(w, 'registrar') else None,
                    "country": w.country if hasattr(w, 'country') else None,
                    "name_servers": w.name_servers if hasattr(w, 'name_servers') else None
                }
        except Exception as e:
            await send_log_update(analysis_id, f"WHOIS lookup failed for {domain}: {str(e)}", "WARNING")

        # DNS resolution
        try:
            await send_log_update(analysis_id, f"Resolving DNS for {domain}")
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5

            # A records
            try:
                answers = resolver.resolve(domain, 'A')
                result["findings"]["dns"] = {
                    "a_records": [str(answer) for answer in answers]
                }
            except Exception:
                pass

            # MX records
            try:
                mx_answers = resolver.resolve(domain, 'MX')
                result["findings"]["dns"]["mx_records"] = [str(mx) for mx in mx_answers]
            except Exception:
                pass

        except Exception as e:
            await send_log_update(analysis_id, f"DNS resolution failed for {domain}: {str(e)}", "WARNING")

        # VirusTotal domain check
        if VIRUSTOTAL_API_KEY:
            await send_log_update(analysis_id, f"Checking VirusTotal for domain {domain}")
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}

            try:
                vt_response = requests.get(
                    f"https://www.virustotal.com/api/v3/domains/{domain}",
                    headers=headers,
                    timeout=10
                )

                if vt_response.status_code == 200:
                    vt_data = vt_response.json()
                    stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    result["findings"]["virustotal"] = {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "clean": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                        "categories": vt_data.get("data", {}).get("attributes", {}).get("categories", {}),
                        "reputation": vt_data.get("data", {}).get("attributes", {}).get("reputation", 0)
                    }
                else:
                    await send_log_update(analysis_id, f"VirusTotal domain check failed: {vt_response.status_code}", "WARNING")
            except Exception as e:
                await send_log_update(analysis_id, f"VirusTotal domain check error: {str(e)}", "WARNING")

    except Exception as e:
        logger.error(f"Domain analysis failed for {domain}: {e}")
        result["error"] = str(e)
        await send_log_update(analysis_id, f"Domain analysis error for {domain}: {str(e)}", "ERROR")

    return result

# ---------------- Email Header Analysis ----------------
async def analyze_email_headers(analysis_id: str, headers: str) -> Dict[str, Any]:
    """Analyze email headers for authentication, routing, and suspicious indicators"""
    result = {"raw_headers": headers, "findings": {}, "extracted_data": {"public_ips": [], "domains": []}}

    try:
        await send_log_update(analysis_id, "Parsing email headers")

        # Parse headers
        msg = email.message_from_string(headers)
        parsed_headers = {}

        for key, value in msg.items():
            if key.lower() in parsed_headers:
                if isinstance(parsed_headers[key.lower()], list):
                    parsed_headers[key.lower()].append(value)
                else:
                    parsed_headers[key.lower()] = [parsed_headers[key.lower()], value]
            else:
                parsed_headers[key.lower()] = value

        result["findings"]["parsed_headers"] = parsed_headers

        # Extract IPs and domains
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        domain_pattern = r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*'

        # Extract from received headers
        received_headers = msg.get_all('Received', [])
        for received in received_headers:
            # Extract IPs
            ips = re.findall(ip_pattern, received)
            for ip in ips:
                if is_valid_ip(ip) and not is_private_ip(ip) and ip not in result["extracted_data"]["public_ips"]:
                    result["extracted_data"]["public_ips"].append(ip)

            # Extract domains
            domains = re.findall(domain_pattern, received)
            for domain in domains:
                if '.' in domain and domain not in result["extracted_data"]["domains"]:
                    result["extracted_data"]["domains"].append(domain)

        # Enhanced authentication analysis
        auth_results = {}

        # SPF Analysis
        spf_header = parsed_headers.get('received-spf', '')
        if spf_header:
            if isinstance(spf_header, list):
                spf_header = spf_header[0]

            spf_status = 'unknown'
            if 'pass' in spf_header.lower():
                spf_status = 'pass'
            elif 'fail' in spf_header.lower():
                spf_status = 'fail'
            elif 'softfail' in spf_header.lower():
                spf_status = 'softfail'
            elif 'neutral' in spf_header.lower():
                spf_status = 'neutral'

            auth_results['spf'] = {
                'status': spf_status,
                'raw': spf_header
            }
        else:
            auth_results['spf'] = {
                'status': 'not_found',
                'raw': None
            }

        # DKIM Analysis
        dkim_signature = parsed_headers.get('dkim-signature', '')
        if dkim_signature:
            if isinstance(dkim_signature, list):
                dkim_signature = dkim_signature[0]

            auth_results['dkim'] = {
                'status': 'present',
                'raw': dkim_signature
            }
        else:
            auth_results['dkim'] = {
                'status': 'not_found',
                'raw': None
            }

        # DMARC Analysis
        auth_header = parsed_headers.get('authentication-results', '')
        if auth_header:
            if isinstance(auth_header, list):
                auth_header = auth_header[0]

            dmarc_status = 'unknown'
            if 'dmarc=pass' in auth_header.lower():
                dmarc_status = 'pass'
            elif 'dmarc=fail' in auth_header.lower():
                dmarc_status = 'fail'
            elif 'dmarc=' in auth_header.lower():
                dmarc_status = 'present'

            auth_results['dmarc'] = {
                'status': dmarc_status,
                'raw': auth_header
            }
        else:
            auth_results['dmarc'] = {
                'status': 'not_found',
                'raw': None
            }

        result["findings"]["authentication"] = auth_results

        await send_log_update(analysis_id, f"Extracted {len(result['extracted_data']['public_ips'])} public IPs and {len(result['extracted_data']['domains'])} domains")

    except Exception as e:
        logger.error(f"Email header analysis failed: {e}")
        result["error"] = str(e)
        await send_log_update(analysis_id, f"Email header analysis error: {str(e)}", "ERROR")

    return result

# ---------------- URL Analysis ----------------
async def analyze_url(analysis_id: str, url: str) -> Dict[str, Any]:
    """Analyze URL for malicious indicators"""
    result = {"url": url, "findings": {}}

    try:
        await send_log_update(analysis_id, f"Analyzing URL: {url}")

        # Normalize URL
        normalized_url = normalize_url(url)
        parsed = urlparse(normalized_url)

        result["normalized_url"] = normalized_url
        result["parsed"] = {
            "scheme": parsed.scheme,
            "netloc": parsed.netloc,
            "path": parsed.path,
            "params": parsed.params,
            "query": parsed.query,
            "fragment": parsed.fragment
        }

        # VirusTotal URL check
        if VIRUSTOTAL_API_KEY:
            await send_log_update(analysis_id, f"Checking VirusTotal for {normalized_url}")
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}

            try:
                # Use the normalized URL for VT check
                vt_url_id = base64.urlsafe_b64encode(normalized_url.encode()).decode().strip("=")

                vt_response = requests.get(
                    f"https://www.virustotal.com/api/v3/urls/{vt_url_id}",
                    headers=headers,
                    timeout=10
                )

                if vt_response.status_code == 200:
                    vt_data = vt_response.json()
                    stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    result["findings"]["virustotal"] = {
                        "status": "known",
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "clean": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                        "scan_date": vt_data.get("data", {}).get("attributes", {}).get("last_analysis_date")
                    }
                    await send_log_update(analysis_id, f"VirusTotal: {stats.get('malicious', 0)} malicious detections")

                elif vt_response.status_code == 404:
                    await send_log_update(analysis_id, "URL not found on VT. Submitting for analysis...")
                    submit_response = requests.post(
                        "https://www.virustotal.com/api/v3/urls",
                        headers=headers,
                        data={"url": normalized_url},
                        timeout=15
                    )

                    if submit_response.status_code == 200:
                        submit_data = submit_response.json()
                        analysis_id_vt = submit_data.get("data", {}).get("id")
                        await send_log_update(analysis_id, "Waiting for VirusTotal analysis...")

                        # Poll for results
                        for attempt in range(12):  # Wait up to 1 minute
                            await asyncio.sleep(5)
                            poll_response = requests.get(
                                f"https://www.virustotal.com/api/v3/analyses/{analysis_id_vt}",
                                headers=headers,
                                timeout=15
                            )

                            if poll_response.status_code == 200:
                                poll_data = poll_response.json()
                                status = poll_data.get("data", {}).get("attributes", {}).get("status")

                                if status == "completed":
                                    stats = poll_data.get("data", {}).get("attributes", {}).get("stats", {})
                                    result["findings"]["virustotal"] = {
                                        "status": "newly_analyzed",
                                        "malicious": stats.get("malicious", 0),
                                        "suspicious": stats.get("suspicious", 0),
                                        "clean": stats.get("harmless", 0),
                                        "undetected": stats.get("undetected", 0)
                                    }
                                    await send_log_update(analysis_id, f"VirusTotal analysis complete: {stats.get('malicious', 0)} malicious detections")
                                    break
                                elif attempt == 11:  # Last attempt
                                    result["findings"]["virustotal"] = {"status": "analysis_timeout"}
                                    await send_log_update(analysis_id, "VirusTotal analysis timeout", "WARNING")
                        else:
                            result["findings"]["virustotal"] = {"status": "analysis_pending"}
                    else:
                        result["findings"]["virustotal"] = {"status": "submission_failed"}
                        await send_log_update(analysis_id, f"VT submission failed: {submit_response.status_code}", "WARNING")
                else:
                    await send_log_update(analysis_id, f"VirusTotal check failed: {vt_response.status_code}", "WARNING")
                    result["findings"]["virustotal"] = {"status": f"api_error_{vt_response.status_code}"}

            except Exception as e:
                await send_log_update(analysis_id, f"VirusTotal check error: {str(e)}", "WARNING")
                logger.error(f"VirusTotal URL check failed: {e}")

        # Analyze domain if present
        if parsed.netloc:
            await send_log_update(analysis_id, f"Analyzing domain: {parsed.netloc}")
            domain_result = await analyze_domain(analysis_id, parsed.netloc)
            result["findings"]["domain_analysis"] = domain_result["findings"]

    except Exception as e:
        logger.error(f"URL analysis failed for {url}: {e}")
        result["error"] = str(e)
        await send_log_update(analysis_id, f"URL analysis error: {str(e)}", "ERROR")

    return result

# ---------------- File Analysis ----------------
async def analyze_file(analysis_id: str, file_content: bytes, filename: str) -> Dict[str, Any]:
    """Analyze uploaded file for malicious indicators"""
    result = {"filename": filename, "findings": {}}

    try:
        await send_log_update(analysis_id, f"Analyzing file: {filename}")

        # Basic file info
        result["file_info"] = {
            "size": len(file_content),
            "filename": filename,
            "hashes": get_file_hash(file_content)
        }

        # File type detection
        try:
            file_type = magic.from_buffer(file_content, mime=True)
            result["file_info"]["mime_type"] = file_type
            result["file_info"]["file_type"] = magic.from_buffer(file_content)
        except Exception as e:
            logger.warning(f"File type detection failed: {e}")
            result["file_info"]["mime_type"] = "unknown"
            result["file_info"]["file_type"] = "unknown"

        # YARA scanning
        if yara_rules:
            await send_log_update(analysis_id, "Running YARA rules scan")
            try:
                matches = yara_rules.match(data=file_content)
                result["findings"]["yara_matches"] = [
                    {
                        "rule": m.rule,
                        "meta": dict(m.meta) if m.meta else {},
                        "strings": [(s.identifier, len(s.instances)) for s in m.strings]
                    }
                    for m in matches
                ]
                if matches:
                    await send_log_update(analysis_id, f"YARA detected {len(matches)} rule matches", "WARNING")
            except Exception as e:
                logger.warning(f"YARA scan failed: {e}")
                result["findings"]["yara_matches"] = []

        # VirusTotal file check
        if VIRUSTOTAL_API_KEY:
            await send_log_update(analysis_id, "Checking file hash against VirusTotal")
            try:
                file_hash = result["file_info"]["hashes"]["sha256"]
                headers = {"x-apikey": VIRUSTOTAL_API_KEY}

                vt_response = requests.get(
                    f"https://www.virustotal.com/api/v3/files/{file_hash}",
                    headers=headers,
                    timeout=10
                )

                if vt_response.status_code == 200:
                    vt_data = vt_response.json()
                    stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    result["findings"]["virustotal"] = {
                        "status": "known",
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "clean": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                        "scan_date": vt_data.get("data", {}).get("attributes", {}).get("last_analysis_date")
                    }
                    await send_log_update(analysis_id, f"VirusTotal: {stats.get('malicious', 0)} malicious detections")

                elif vt_response.status_code == 404:
                    await send_log_update(analysis_id, "File not found on VirusTotal. Uploading for analysis...")

                    # File upload size limit (32MB for VT)
                    if len(file_content) > 32 * 1024 * 1024:
                        result["findings"]["virustotal"] = {"status": "file_too_large"}
                        await send_log_update(analysis_id, "File too large for VirusTotal upload", "WARNING")
                    else:
                        files = {"file": (filename, file_content)}
                        upload_response = requests.post(
                            "https://www.virustotal.com/api/v3/files",
                            headers=headers,
                            files=files,
                            timeout=60
                        )

                        if upload_response.status_code == 200:
                            upload_data = upload_response.json()
                            analysis_id_vt = upload_data.get("data", {}).get("id")
                            await send_log_update(analysis_id, "Waiting for VirusTotal file analysis...")

                            # Poll for results
                            for attempt in range(20):  # Wait up to 100 seconds
                                await asyncio.sleep(5)
                                poll_response = requests.get(
                                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id_vt}",
                                    headers=headers,
                                    timeout=15
                                )

                                if poll_response.status_code == 200:
                                    poll_data = poll_response.json()
                                    status = poll_data.get("data", {}).get("attributes", {}).get("status")

                                    if status == "completed":
                                        stats = poll_data.get("data", {}).get("attributes", {}).get("stats", {})
                                        result["findings"]["virustotal"] = {
                                            "status": "newly_analyzed",
                                            "malicious": stats.get("malicious", 0),
                                            "suspicious": stats.get("suspicious", 0),
                                            "clean": stats.get("harmless", 0),
                                            "undetected": stats.get("undetected", 0)
                                        }
                                        await send_log_update(analysis_id, f"VirusTotal file analysis complete: {stats.get('malicious', 0)} malicious detections")
                                        break
                                elif attempt == 19:  # Last attempt
                                    result["findings"]["virustotal"] = {"status": "analysis_timeout"}
                                    await send_log_update(analysis_id, "VirusTotal file analysis timeout", "WARNING")
                            else:
                                result["findings"]["virustotal"] = {"status": "analysis_pending"}
                        else:
                            result["findings"]["virustotal"] = {"status": "upload_failed"}
                            await send_log_update(analysis_id, f"VT upload failed: {upload_response.status_code}", "WARNING")
                else:
                    await send_log_update(analysis_id, f"VirusTotal file check failed: {vt_response.status_code}", "WARNING")

            except Exception as e:
                logger.warning(f"VirusTotal file check failed: {e}")
                result["findings"]["virustotal"] = {"status": "api_error", "error": str(e)}

        # Entropy analysis
        if len(file_content) > 0:
            import math
            from collections import Counter

            byte_counts = Counter(file_content)
            entropy = -sum((c / len(file_content)) * math.log2(c / len(file_content)) for c in byte_counts.values())
            result["findings"]["entropy"] = {
                "value": round(entropy, 2),
                "assessment": "high" if entropy > 7.5 else "medium" if entropy > 6.5 else "low"
            }

            if entropy > 7.5:
                await send_log_update(analysis_id, f"High entropy detected: {entropy:.2f} (possible encryption/packing)", "WARNING")

        await send_log_update(analysis_id, f"File analysis completed for {filename}")

    except Exception as e:
        logger.error(f"File analysis failed for {filename}: {e}")
        result["error"] = str(e)
        await send_log_update(analysis_id, f"File analysis error: {str(e)}", "ERROR")

    return result


# API Endpoints

@app.websocket("/ws/{analysis_id}")
async def websocket_endpoint(websocket: WebSocket, analysis_id: str):
    """WebSocket endpoint for real-time log streaming"""
    await websocket.accept()
    websocket_connections[analysis_id] = websocket

    try:
        while True:
            await websocket.receive_text()  # Keep connection alive
    except WebSocketDisconnect:
        if analysis_id in websocket_connections:
            del websocket_connections[analysis_id]

@app.post("/analyze/header")
async def analyze_header_endpoint(request: AnalysisRequest):
    """Analyze email headers"""
    analysis_id = str(uuid.uuid4())

    # Initialize cache entry
    cache[analysis_id] = {
        "analysis_id": analysis_id,
        "status": "running",
        "findings": {},
        "logs": [],
        "created_at": datetime.now(),
        "summary": {}
    }

    try:
        await send_log_update(analysis_id, "Starting email header analysis")

        # Analyze headers
        header_result = await analyze_email_headers(analysis_id, request.headers)

        # Store findings without raw headers
        header_findings = {
            "findings": header_result["findings"],
            "extracted_data": header_result["extracted_data"]
        }
        if "error" in header_result:
            header_findings["error"] = header_result["error"]

        cache[analysis_id]["findings"]["headers"] = header_findings

        # Analyze extracted IPs
        ip_results = []
        for ip in header_result.get("extracted_data", {}).get("public_ips", []):
            ip_result = await analyze_ip_address(analysis_id, ip)
            ip_results.append(ip_result)
        cache[analysis_id]["findings"]["ips"] = ip_results

        # Analyze extracted domains
        domain_results = []
        for domain in header_result.get("extracted_data", {}).get("domains", []):
            domain_result = await analyze_domain(analysis_id, domain)
            domain_results.append(domain_result)
        cache[analysis_id]["findings"]["domains"] = domain_results

        # Generate enhanced summary
        suspicious_ips = len([ip for ip in ip_results if ip.get("findings", {}).get("abuseipdb", {}).get("abuse_confidence", 0) > 50])
        malicious_domains = len([d for d in domain_results if d.get("findings", {}).get("virustotal", {}).get("malicious", 0) > 0])

        # Authentication summary
        auth_data = header_result.get("findings", {}).get("authentication", {})
        spf_status = auth_data.get("spf", {}).get("status", "not_found")
        dkim_status = auth_data.get("dkim", {}).get("status", "not_found")
        dmarc_status = auth_data.get("dmarc", {}).get("status", "not_found")

        cache[analysis_id]["summary"] = {
            "total_ips_analyzed": len(ip_results),
            "total_domains_analyzed": len(domain_results),
            "suspicious_ips": suspicious_ips,
            "malicious_domains": malicious_domains,
            "spf_status": spf_status,
            "dkim_status": dkim_status,
            "dmarc_status": dmarc_status,
            "authentication_score": sum([
                1 if spf_status == "pass" else 0,
                1 if dkim_status == "present" else 0,
                1 if dmarc_status == "pass" else 0
            ]),
            "risk_level": "high" if (suspicious_ips > 0 or malicious_domains > 0) else "medium" if (spf_status == "fail" or dmarc_status == "fail") else "low"
        }

        cache[analysis_id]["status"] = "completed"
        await send_log_update(analysis_id, "Email header analysis completed", "SUCCESS")

        return {"analysis_id": analysis_id, "status": "completed"}

    except Exception as e:
        logger.error(f"Header analysis failed: {e}")
        cache[analysis_id]["status"] = "failed"
        cache[analysis_id]["error"] = str(e)
        await send_log_update(analysis_id, f"Analysis failed: {str(e)}", "ERROR")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/url")
async def analyze_url_endpoint(request: AnalysisRequest):
    """Analyze URLs"""
    analysis_id = str(uuid.uuid4())

    cache[analysis_id] = {
        "analysis_id": analysis_id,
        "status": "running",
        "findings": {},
        "logs": [],
        "created_at": datetime.now(),
        "summary": {}
    }

    try:
        await send_log_update(analysis_id, f"Starting URL analysis for {len(request.urls)} URLs")

        url_results = []
        for url in request.urls:
            url_result = await analyze_url(analysis_id, url)
            url_results.append(url_result)

        cache[analysis_id]["findings"]["urls"] = url_results

        # Generate enhanced summary
        malicious_urls = len([url for url in url_results if url.get("findings", {}).get("virustotal", {}).get("malicious", 0) > 0])
        suspicious_urls = len([url for url in url_results if url.get("findings", {}).get("virustotal", {}).get("suspicious", 0) > 0])
        malicious_domains = len([url for url in url_results if url.get("findings", {}).get("domain_analysis", {}).get("virustotal", {}).get("malicious", 0) > 0])

        cache[analysis_id]["summary"] = {
            "total_urls_analyzed": len(url_results),
            "malicious_urls": malicious_urls,
            "suspicious_urls": suspicious_urls,
            "malicious_domains": malicious_domains,
            "risk_level": "high" if malicious_urls > 0 else "medium" if suspicious_urls > 0 else "low"
        }

        cache[analysis_id]["status"] = "completed"
        await send_log_update(analysis_id, f"URL analysis completed. {malicious_urls} malicious URLs detected", "SUCCESS")

        return {"analysis_id": analysis_id, "status": "completed"}

    except Exception as e:
        logger.error(f"URL analysis failed: {e}")
        cache[analysis_id]["status"] = "failed"
        cache[analysis_id]["error"] = str(e)
        await send_log_update(analysis_id, f"Analysis failed: {str(e)}", "ERROR")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/attachment")
async def analyze_attachment_endpoint(file: UploadFile = File(...)):
    """Analyze uploaded file attachment"""
    analysis_id = str(uuid.uuid4())

    cache[analysis_id] = {
        "analysis_id": analysis_id,
        "status": "running",
        "findings": {},
        "logs": [],
        "created_at": datetime.now(),
        "summary": {}
    }

    try:
        await send_log_update(analysis_id, f"Starting file analysis for {file.filename}")

        # Read file content
        file_content = await file.read()

        # Analyze file
        file_result = await analyze_file(analysis_id, file_content, file.filename)
        cache[analysis_id]["findings"]["file"] = file_result

        # Generate enhanced summary
        yara_matches = len(file_result.get("findings", {}).get("yara_matches", []))
        vt_malicious = file_result.get("findings", {}).get("virustotal", {}).get("malicious", 0)
        entropy_level = file_result.get("findings", {}).get("entropy", {}).get("assessment", "low")

        # Determine risk level
        risk_level = "low"
        if yara_matches > 0 or vt_malicious > 5:
            risk_level = "high"
        elif vt_malicious > 0 or entropy_level == "high":
            risk_level = "medium"

        cache[analysis_id]["summary"] = {
            "file_size": len(file_content),
            "file_type": file_result.get("file_info", {}).get("file_type", "unknown"),
            "mime_type": file_result.get("file_info", {}).get("mime_type", "unknown"),
            "yara_matches": yara_matches,
            "virustotal_detections": vt_malicious,
            "entropy_level": entropy_level,
            "entropy_value": file_result.get("findings", {}).get("entropy", {}).get("value", 0),
            "risk_level": risk_level
        }

        cache[analysis_id]["status"] = "completed"
        await send_log_update(analysis_id, f"File analysis completed. Risk level: {risk_level}", "SUCCESS")

        return {"analysis_id": analysis_id, "status": "completed"}

    except Exception as e:
        logger.error(f"File analysis failed: {e}")
        cache[analysis_id]["status"] = "failed"
        cache[analysis_id]["error"] = str(e)
        await send_log_update(analysis_id, f"Analysis failed: {str(e)}", "ERROR")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/results/{analysis_id}")
async def get_results(analysis_id: str):
    """Get analysis results"""
    if analysis_id not in cache:
        raise HTTPException(status_code=404, detail="Analysis not found or expired")

    return cache[analysis_id]

@app.delete("/results/{analysis_id}")
async def clear_results(analysis_id: str):
    """Clear analysis results from memory"""
    if analysis_id in cache:
        del cache[analysis_id]
    if analysis_id in websocket_connections:
        del websocket_connections[analysis_id]

    return {"message": "Analysis data cleared"}

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    api_status = {
        "virustotal": bool(VIRUSTOTAL_API_KEY),
        "abuseipdb": bool(ABUSEIPDB_API_KEY),
        "hybrid_analysis": bool(HYBRID_ANALYSIS_API_KEY)
    }

    return {
        "status": "healthy",
        "cache_size": len(cache),
        "websocket_connections": len(websocket_connections),
        "api_keys_configured": api_status,
        "yara_rules_loaded": yara_rules is not None
    }

@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "name": "Ephemeral Email Analysis Tool",
        "version": "1.0.0",
        "endpoints": {
            "analyze_header": "/analyze/header",
            "analyze_url": "/analyze/url",
            "analyze_attachment": "/analyze/attachment",
            "get_results": "/results/{analysis_id}",
            "websocket": "/ws/{analysis_id}",
            "health": "/health"
        },
        "features": [
            "Email header analysis with authentication checks",
            "URL reputation analysis via VirusTotal",
            "File malware scanning with YARA rules",
            "IP address reputation checking",
            "Domain WHOIS and DNS analysis",
            "Real-time analysis logging via WebSocket",
            "TTL-based memory caching for security"
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)