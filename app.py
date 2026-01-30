import os
import ssl
import socket
import whois
import requests
import tldextract
import math
import textdistance
import concurrent.futures
from flask import Flask, render_template, request, jsonify
from datetime import datetime
from fake_useragent import UserAgent
from dotenv import load_dotenv

# Load environment variables (API Keys)
load_dotenv()

app = Flask(__name__)
ua = UserAgent()

# --- 1. CONFIGURATION & FREE API KEYS ---
# You can get these keys for FREE.
# Google: https://console.cloud.google.com/ (Enable Safe Browsing API)
# VirusTotal: https://www.virustotal.com/gui/join-us (Public API)
GOOGLE_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# --- 2. GLOBAL WHITELIST (The "No Mistake" List) ---
# Extensive list of trusted domains to prevent false positives.
TRUSTED_GIANTS = {
    # Global Tech
    "google", "youtube", "facebook", "amazon", "apple", "microsoft", "netflix", 
    "instagram", "linkedin", "ebay", "paypal", "twitter", "x", "wikipedia", 
    "yahoo", "whatsapp", "tiktok", "twitch", "reddit", "pinterest", "zoom", 
    "adobe", "github", "gitlab", "stackoverflow", "dropbox", "salesforce",
    "shopify", "spotify", "hulu", "disneyplus", "airbnb", "uber", "booking",
    # Finance
    "chase", "paypal", "stripe", "revolut", "wise", "mastercard", "visa",
    # Hungarian / Regional
    "arukereso", "emag", "jofogas", "index", "telex", "otpbank", "telekom", 
    "vodafone", "yettel", "ingatlan", "hasznaltauto", "vatera", "port", "origo",
    "24", "hvg", "portfolio", "ncore", "gov", "police", "nav", "simplepay"
}

# --- 3. HELPER FUNCTIONS ---

def get_ssl_details(domain):
    """Checks if the site has an Organization Validated (OV/EV) certificate."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                return {
                    "valid": True,
                    "org": subject.get('organizationName'), # Critical for trust
                    "cn": subject.get('commonName')
                }
    except:
        return {"valid": False, "org": None}

def calculate_entropy(string):
    """Math: Detects random domains like 'x839a.com'."""
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

def check_typosquatting(domain_name):
    """Math: Checks if domain looks like a giant (e.g. 'amaz0n')."""
    for giant in TRUSTED_GIANTS:
        # If very similar but not identical
        similarity = textdistance.jaro_winkler(domain_name, giant)
        if 0.85 < similarity < 1.0:
            return True, giant
    return False, None

def check_google_api(url):
    """Queries Google Safe Browsing (Free Tier)."""
    if not GOOGLE_KEY: return None
    try:
        payload = {
            "client": {"clientId": "webguard", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        r = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_KEY}", json=payload, timeout=2)
        return True if (r.status_code == 200 and r.json()) else False
    except:
        return None

def check_virustotal_api(url):
    """Queries VirusTotal (Free Tier - 4 lookups/min)."""
    if not VT_KEY: return None
    try:
        # Need to encode URL for VT
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_KEY}
        r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=3)
        if r.status_code == 200:
            stats = r.json()['data']['attributes']['last_analysis_stats']
            return stats['malicious'] > 0
        return False
    except:
        return None

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    raw_url = data.get('url', '').strip()
    
    if not raw_url: return jsonify({"error": "No URL"}), 400

    if not raw_url.startswith(('http://', 'https://')):
        url = 'https://' + raw_url
    else:
        url = raw_url

    results = {"score": 0, "logs": [], "details": {}}
    
    try:
        # --- 1. PARSE & UNFURL ---
        # Follow redirects (e.g. bit.ly -> malware.com)
        try:
            session = requests.Session()
            session.headers.update({'User-Agent': ua.random})
            resp = session.head(url, allow_redirects=True, timeout=5)
            final_url = resp.url
        except:
            final_url = url # If fail, assume no redirect

        ext = tldextract.extract(final_url)
        root_domain = f"{ext.domain}.{ext.suffix}"
        full_domain = f"{ext.subdomain}.{ext.domain}.{ext.suffix}" if ext.subdomain else root_domain

        # --- 2. INSTANT WHITELIST (Layer 0) ---
        if ext.domain in TRUSTED_GIANTS:
            return jsonify({
                "score": 100,
                "risk_level": "SAFE",
                "details": {"domain": full_domain, "age": "Verified Giant", "ssl": True, "org": f"Official {ext.domain.capitalize()}"},
                "logs": [{"type": "success", "msg": f"Verified Trustworthy Domain ({ext.domain.capitalize()})."}]
            })

        # --- 3. GATHER INTEL (Parallel Execution) ---
        ssl_info = get_ssl_details(full_domain)
        
        # Domain Age
        age_days = None
        try:
            w = whois.whois(root_domain)
            cd = w.creation_date
            if isinstance(cd, list): cd = cd[0]
            if cd: age_days = (datetime.now() - cd).days
        except:
            pass

        # Math Checks
        entropy = calculate_entropy(ext.domain)
        is_typo, target_giant = check_typosquatting(ext.domain)

        # API Checks (Graceful Fallback)
        google_flag = check_google_api(final_url)
        vt_flag = check_virustotal_api(final_url)

        # --- 4. SCORING ENGINE (The Logic) ---
        score = 0
        
        # A. SSL Identity (Max 50)
        if ssl_info['valid']:
            score += 20
            if ssl_info['org']:
                score += 30
                results['logs'].append({"type": "success", "msg": f"Identity Verified: {ssl_info['org']}"})
            else:
                results['logs'].append({"type": "info", "msg": "Standard SSL (Identity Hidden)."})
        else:
            score -= 50
            results['logs'].append({"type": "danger", "msg": "Insecure Connection (No HTTPS)."})

        # B. Age (Max 30)
        if age_days:
            results['details']['age'] = f"{age_days} days"
            if age_days > 1800: score += 30 # > 5 years
            elif age_days > 365: score += 20
            elif age_days < 30: 
                score -= 40
                results['logs'].append({"type": "danger", "msg": "Domain is extremely new (< 1 month)!"})
        else:
            results['details']['age'] = "Hidden"
            if ssl_info['org']: score += 20 # Trust SSL if WHOIS hidden
            else: results['logs'].append({"type": "warning", "msg": "Domain age hidden."})

        # C. Heuristics (Penalties)
        if entropy > 4.2:
            score -= 20
            results['logs'].append({"type": "warning", "msg": "Domain name looks random/generated."})
        
        if is_typo:
            score = 0
            results['logs'].append({"type": "danger", "msg": f"Phishing Risk! Looks like {target_giant}."})

        # D. API Vetos (The Kill Switch)
        if google_flag is True or vt_flag is True:
            score = 0
            results['logs'].append({"type": "danger", "msg": "Flagged as MALICIOUS by Global Blacklists."})
        elif google_flag is False:
             score += 10
             results['logs'].append({"type": "success", "msg": "Clean on Google Safe Browsing."})

        # --- 5. FINISH ---
        score = max(0, min(100, score))
        if score >= 80: risk = "SAFE"
        elif score >= 50: risk = "CAUTION"
        else: risk = "DANGER"

        results['score'] = score
        results['risk_level'] = risk
        results['details']['domain'] = full_domain
        results['details']['ssl'] = ssl_info['valid']
        results['details']['org'] = ssl_info['org'] or "Not Listed"

        return jsonify(results)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)