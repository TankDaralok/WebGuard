import ssl
import socket
import whois
import requests
import dns.resolver
import textdistance
import math
import urllib.parse
import tldextract
import concurrent.futures
from flask import Flask, render_template, request, jsonify
from datetime import datetime
from bs4 import BeautifulSoup
from fake_useragent import UserAgent

app = Flask(__name__)

# --- CONFIGURATION ---
# High-trust domains whitelist (prevents false positives on giants)
TRUSTED_GIANTS = {
    "google.com", "facebook.com", "amazon.com", "apple.com", "microsoft.com", 
    "netflix.com", "instagram.com", "linkedin.com", "ebay.com", "paypal.com",
    "twitter.com", "wikipedia.org", "yahoo.com", "whatsapp.com", "arukereso.hu",
    "emag.hu", "jofogas.hu", "index.hu", "telex.hu", "otpbank.hu"
}

ua = UserAgent()

def get_ssl_details(domain):
    """
    Connects to port 443 and extracts the certificate 'Organization' (O) field.
    Real businesses have an 'O' field (e.g., 'Amazon.com, Inc.').
    Scams usually have None or 'Let's Encrypt' without an O field.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Extract Subject details
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])
                
                org = subject.get('organizationName')
                common_name = subject.get('commonName')
                
                return {
                    "valid": True,
                    "org": org,
                    "issuer": issuer.get('organizationName'),
                    "common_name": common_name
                }
    except Exception as e:
        return {"valid": False, "error": str(e)}

def analyze_headers(url):
    """Checks for security headers that sophisticated sites use but scams skip."""
    try:
        headers = {'User-Agent': ua.random}
        response = requests.head(url, headers=headers, timeout=5, allow_redirects=True)
        
        sec_headers = {
            "HSTS": "strict-transport-security" in response.headers,
            "X-Frame": "x-frame-options" in response.headers,
            "X-Content": "x-content-type-options" in response.headers
        }
        return sec_headers, response.status_code
    except:
        return {"HSTS": False, "X-Frame": False}, 0

def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if not creation_date:
            return None, "Hidden"

        now = datetime.now()
        age_days = (now - creation_date).days
        return age_days, creation_date.strftime('%Y-%m-%d')
    except:
        return None, "Unknown"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    raw_url = data.get('url', '').strip()
    
    if not raw_url:
        return jsonify({"error": "No URL provided"}), 400

    # URL Standardization
    if not raw_url.startswith(('http://', 'https://')):
        url = 'https://' + raw_url
    else:
        url = raw_url

    try:
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        full_domain = f"{ext.subdomain}.{ext.domain}.{ext.suffix}" if ext.subdomain else domain
        
        logs = []
        score = 0
        risk_level = "LOW"
        
        # --- 1. WHITELIST CHECK (Instant Pass) ---
        if domain in TRUSTED_GIANTS:
            return jsonify({
                "score": 100,
                "risk_level": "SAFE",
                "details": {
                    "domain": full_domain,
                    "age": "Verified Giant",
                    "ssl": True,
                    "org": "Verified Entity"
                },
                "logs": [{"type": "success", "msg": f"Verified Trustworthy Domain (Global Top 500 / Trusted Local)."}]
            })

        # --- 2. SSL DEEP SCAN (The "Enterprise" Check) ---
        ssl_info = get_ssl_details(full_domain)
        has_ssl = ssl_info['valid']
        
        # --- 3. DOMAIN AGE ---
        age_days, creation_date = get_domain_age(domain)

        # --- 4. HEADER & CONNECTIVITY ---
        sec_headers, status_code = analyze_headers(url)

        # --- SCORING LOGIC V2 (Robust) ---
        
        # A. SSL Scoring (Max 40)
        if has_ssl:
            if ssl_info.get('org'): 
                score += 40
                logs.append({"type": "success", "msg": f"Verified Business Identity: {ssl_info['org']}"})
            else:
                score += 15
                logs.append({"type": "warning", "msg": "Standard SSL (DV). No Company Name in certificate."})
        else:
            score -= 20
            logs.append({"type": "danger", "msg": "No Secure Connection (HTTPS)."})

        # B. Domain Age (Max 30)
        if age_days:
            if age_days > 3650: # 10 years
                score += 30
            elif age_days > 1095: # 3 years
                score += 25
            elif age_days > 365:
                score += 15
            elif age_days < 90:
                score -= 20
                logs.append({"type": "danger", "msg": "Domain is extremely new (< 3 months)."})
        else:
            # If WHOIS failed but SSL has Org name, trust the SSL
            if ssl_info.get('org'):
                score += 20 
                logs.append({"type": "info", "msg": "Domain age hidden, but trusted via Certificate."})
            else:
                logs.append({"type": "warning", "msg": "Could not determine domain age."})

        # C. Technical Security (Max 20)
        if sec_headers['HSTS']: score += 10
        if sec_headers['X-Frame']: score += 5
        if sec_headers['X-Content']: score += 5

        # D. Content / Bot Protection Fallback
        # If we got blocked (403/503) but have valid EV SSL (Org Name), we ignore the block
        if status_code in [403, 503, 999] and ssl_info.get('org'):
            logs.append({"type": "info", "msg": "Site blocked scraping, but Identity is Verified via SSL."})
            score += 10 # Compensation points
        elif status_code == 200:
             # Basic keyword check
             try:
                r = requests.get(url, headers={'User-Agent': ua.random}, timeout=3)
                text = r.text.lower()
                if "privacy" in text or "adatvédel" in text: score += 5
                if "contact" in text or "kapcsolat" in text: score += 5
             except:
                pass

        # Typosquatting Check (Prevent amazon-shop.com)
        if "amazon" in domain and domain != "amazon.com":
            score -= 50
            logs.append({"type": "danger", "msg": "Possible Impersonation of Amazon."})
            
        # --- FINAL CALCULATIONS ---
        score = max(0, min(100, score))
        
        if score >= 80: risk_level = "SAFE"
        elif score >= 50: risk_level = "CAUTION"
        else: risk_level = "DANGER"

        return jsonify({
            "score": score,
            "risk_level": risk_level,
            "details": {
                "domain": full_domain,
                "age": f"{age_days} days" if age_days else "Unknown",
                "ssl": has_ssl,
                "org": ssl_info.get('org', 'Not Listed'),
                "issuer": ssl_info.get('issuer', 'Unknown')
            },
            "logs": logs
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)