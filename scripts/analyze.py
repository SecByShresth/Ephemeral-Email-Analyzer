#!/usr/bin/env python3
"""
GitHub Actions Email Analysis Script
Converted from FastAPI backend to serverless function
"""

import json
import os
import sys
import re
import base64
import hashlib
import requests
import time
from datetime import datetime
from urllib.parse import urlparse
import ipaddress

# Get environment variables
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')
ANALYSIS_TYPE = os.getenv('ANALYSIS_TYPE')
ANALYSIS_DATA = os.getenv('ANALYSIS_DATA')
ANALYSIS_ID = os.getenv('ANALYSIS_ID')

def log_message(message, level="INFO"):
    """Log message with timestamp"""
    timestamp = datetime.now().isoformat()
    print(f"[{timestamp}] [{level}] {message}", file=sys.stderr)

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def analyze_ip_address(ip):
    """Analyze IP address"""
    result = {"ip": ip, "findings": {}}
    
    if is_private_ip(ip):
        result["findings"]["status"] = "private_ip"
        return result
    
    # AbuseIPDB check
    if ABUSEIPDB_API_KEY:
        log_message(f"Checking AbuseIPDB for {ip}")
        try:
            headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                data = response.json().get("data", {})
                result["findings"]["abuseipdb"] = {
                    "abuse_confidence": data.get("abuseConfidencePercentage", 0),
                    "country_code": data.get("countryCode", "unknown"),
                    "total_reports": data.get("totalReports", 0)
                }
        except Exception as e:
            log_message(f"AbuseIPDB error: {e}", "WARNING")
    
    # VirusTotal IP check
    if VIRUSTOTAL_API_KEY:
        log_message(f"Checking VirusTotal for IP {ip}")
        try:
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            response = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                result["findings"]["virustotal"] = {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "clean": stats.get("harmless", 0)
                }
        except Exception as e:
            log_message(f"VirusTotal IP error: {e}", "WARNING")
    
    return result

def analyze_domain(domain):
    """Analyze domain"""
    result = {"domain": domain, "findings": {}}
    
    # VirusTotal domain check
    if VIRUSTOTAL_API_KEY:
        log_message(f"Checking VirusTotal for domain {domain}")
        try:
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            response = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                result["findings"]["virustotal"] = {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "clean": stats.get("harmless", 0),
                    "reputation": data.get("data", {}).get("attributes", {}).get("reputation", 0)
                }
        except Exception as e:
            log_message(f"VirusTotal domain error: {e}", "WARNING")
    
    return result

def analyze_url(url):
    """Analyze URL"""
    result = {"url": url, "findings": {}}
    
    # Normalize URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    parsed = urlparse(url)
    result["normalized_url"] = url
    
    # VirusTotal URL check
    if VIRUSTOTAL_API_KEY:
        log_message(f"Checking VirusTotal for URL")
        try:
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            vt_url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            response = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{vt_url_id}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                result["findings"]["virustotal"] = {
                    "status": "known",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "clean": stats.get("harmless", 0)
                }
            elif response.status_code == 404:
                # Submit URL for analysis
                log_message("Submitting URL to VirusTotal")
                submit_response = requests.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data={"url": url},
                    timeout=15
                )
                
                if submit_response.status_code == 200:
                    submit_data = submit_response.json()
                    analysis_id_vt = submit_data.get("data", {}).get("id")
                    
                    # Poll for results (max 5 attempts)
                    for i in range(5):
                        time.sleep(5)
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
                                    "clean": stats.get("harmless", 0)
                                }
                                break
        except Exception as e:
            log_message(f"VirusTotal URL error: {e}", "WARNING")
    
    # Analyze domain
    if parsed.netloc:
        result["findings"]["domain_analysis"] = analyze_domain(parsed.netloc)["findings"]
    
    return result

def analyze_email_headers(headers_text):
    """Analyze email headers"""
    result = {"findings": {}, "extracted_data": {"public_ips": [], "domains": []}}
    
    log_message("Parsing email headers")
    
    # Extract IPs and domains
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    
    ips = re.findall(ip_pattern, headers_text)
    for ip in ips:
        if is_valid_ip(ip) and not is_private_ip(ip):
            if ip not in result["extracted_data"]["public_ips"]:
                result["extracted_data"]["public_ips"].append(ip)
    
    # Simple authentication check
    auth_results = {}
    
    if 'received-spf' in headers_text.lower():
        if 'pass' in headers_text.lower():
            auth_results['spf'] = {'status': 'pass'}
        elif 'fail' in headers_text.lower():
            auth_results['spf'] = {'status': 'fail'}
        else:
            auth_results['spf'] = {'status': 'present'}
    else:
        auth_results['spf'] = {'status': 'not_found'}
    
    if 'dkim-signature' in headers_text.lower():
        auth_results['dkim'] = {'status': 'present'}
    else:
        auth_results['dkim'] = {'status': 'not_found'}
    
    result["findings"]["authentication"] = auth_results
    
    return result

def analyze_file(file_data_b64, filename):
    """Analyze file"""
    result = {"filename": filename, "findings": {}}
    
    try:
        file_content = base64.b64decode(file_data_b64)
        
        # File hashes
        file_hash = hashlib.sha256(file_content).hexdigest()
        result["file_info"] = {
            "size": len(file_content),
            "sha256": file_hash
        }
        
        # VirusTotal file check
        if VIRUSTOTAL_API_KEY:
            log_message("Checking file hash against VirusTotal")
            try:
                headers = {"x-apikey": VIRUSTOTAL_API_KEY}
                response = requests.get(
                    f"https://www.virustotal.com/api/v3/files/{file_hash}",
                    headers=headers,
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    result["findings"]["virustotal"] = {
                        "status": "known",
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "clean": stats.get("harmless", 0)
                    }
                else:
                    result["findings"]["virustotal"] = {"status": "not_found"}
            except Exception as e:
                log_message(f"VirusTotal file error: {e}", "WARNING")
        
    except Exception as e:
        result["error"] = str(e)
        log_message(f"File analysis error: {e}", "ERROR")
    
    return result

def main():
    """Main analysis function"""
    try:
        log_message(f"Starting analysis type: {ANALYSIS_TYPE}")
        log_message(f"Analysis ID: {ANALYSIS_ID}")
        
        # Parse input data
        data = json.loads(ANALYSIS_DATA)
        
        results = {
            "analysis_id": ANALYSIS_ID,
            "status": "completed",
            "created_at": datetime.now().isoformat(),
            "findings": {},
            "summary": {}
        }
        
        if ANALYSIS_TYPE == "analyze_header":
            headers = data.get("headers", "")
            header_result = analyze_email_headers(headers)
            results["findings"]["headers"] = header_result
            
            # Analyze extracted IPs
            ip_results = []
            for ip in header_result["extracted_data"]["public_ips"][:5]:  # Limit to 5 IPs
                ip_results.append(analyze_ip_address(ip))
            results["findings"]["ips"] = ip_results
            
            # Summary
            suspicious_ips = len([ip for ip in ip_results 
                                 if ip.get("findings", {}).get("abuseipdb", {}).get("abuse_confidence", 0) > 50])
            
            results["summary"] = {
                "total_ips_analyzed": len(ip_results),
                "suspicious_ips": suspicious_ips,
                "spf_status": header_result["findings"]["authentication"]["spf"]["status"],
                "dkim_status": header_result["findings"]["authentication"]["dkim"]["status"],
                "risk_level": "high" if suspicious_ips > 0 else "low"
            }
        
        elif ANALYSIS_TYPE == "analyze_url":
            urls = data.get("urls", [])
            url_results = []
            for url in urls[:5]:  # Limit to 5 URLs
                url_results.append(analyze_url(url))
            results["findings"]["urls"] = url_results
            
            # Summary
            malicious_urls = len([url for url in url_results 
                                 if url.get("findings", {}).get("virustotal", {}).get("malicious", 0) > 0])
            
            results["summary"] = {
                "total_urls_analyzed": len(url_results),
                "malicious_urls": malicious_urls,
                "risk_level": "high" if malicious_urls > 0 else "low"
            }
        
        elif ANALYSIS_TYPE == "analyze_attachment":
            file_data = data.get("file_data")
            filename = data.get("filename")
            file_result = analyze_file(file_data, filename)
            results["findings"]["file"] = file_result
            
            # Summary
            vt_malicious = file_result.get("findings", {}).get("virustotal", {}).get("malicious", 0)
            results["summary"] = {
                "virustotal_detections": vt_malicious,
                "risk_level": "high" if vt_malicious > 5 else "medium" if vt_malicious > 0 else "low"
            }
        
        # Write results to file
        with open('results.json', 'w') as f:
            json.dump(results, f, indent=2)
        
        log_message("Analysis completed successfully")
        
    except Exception as e:
        log_message(f"Analysis failed: {e}", "ERROR")
        error_result = {
            "analysis_id": ANALYSIS_ID,
            "status": "failed",
            "error": str(e),
            "created_at": datetime.now().isoformat()
        }
        with open('results.json', 'w') as f:
            json.dump(error_result, f, indent=2)
        sys.exit(1)

if __name__ == "__main__":
    main()
