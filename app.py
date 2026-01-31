import os
import ssl
import socket
import whois
import requests
import tldextract
import math
import textdistance
import concurrent.futures
from flask import Flask, render_template, request, jsonify, make_response
from datetime import datetime
from fake_useragent import UserAgent
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
ua = UserAgent()

# --- CONFIGURATION ---
GOOGLE_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# Whitelist (Instant 100% Score)
TRUSTED_GIANTS = {
    "google", "youtube", "facebook", "amazon", "apple", "microsoft", "netflix", 
    "instagram", "linkedin", "ebay", "paypal", "twitter", "x", "wikipedia", 
    "yahoo", "whatsapp", "tiktok", "twitch", "reddit", "pinterest", "zoom", 
    "github", "gitlab", "stackoverflow", "bbc", "cnn", "nytimes", "forbes",
    "arukereso", "emag", "jofogas", "index", "telex", "otpbank", "telekom",
    "simplepay", "szamlazz", "gov", "europa", "antsite" # Added for testing
}

# Domains where hidden WHOIS is normal (GDPR)
GDPR_TLDS = {'eu', 'hu', 'de', 'fr', 'it', 'uk', 'nl', 'at', 'es', 'pl'}

def get_ssl_details(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                return {
                    "valid": True,
                    "org": subject.get('organizationName'),
                    "cn": subject.get('commonName')
                }
    except:
        return {"valid": False, "org": None}

def calculate_entropy(string):
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

def check_google_api(url):
    """Returns True if MALICIOUS, False if CLEAN, None if Error"""
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
        # If response has matches, it is malicious (True). If empty, it is clean (False).
        return True if (r.status_code == 200 and r.json()) else False
    except:
        return None

def check_virustotal_api(url):
    """Returns True if MALICIOUS, False if CLEAN"""
    if not VT_KEY: return None
    try:
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

# --- SEO ROUTES ---
@app.route('/robots.txt')
def robots():
    lines = [
        "User-agent: *",
        "Allow: /",
        "Disallow: /analyze",
        f"Sitemap: {request.url_root}sitemap.xml"
    ]
    response = make_response("\n".join(lines))
    response.headers["Content-Type"] = "text/plain"
    return response

@app.route('/sitemap.xml')
def sitemap():
    pages = [{"loc": request.url_root, "changefreq": "daily", "priority": "1.0"}]
    xml = ['<?xml version="1.0" encoding="UTF-8"?>', '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for page in pages:
        xml.append(f'<url><loc>{page["loc"]}</loc><changefreq>{page["changefreq"]}</changefreq><priority>{page["priority"]}</priority><lastmod>{datetime.now().strftime("%Y-%m-%d")}</lastmod></url>')
    xml.append('</urlset>')
    response = make_response("\n".join(xml))
    response.headers["Content-Type"] = "application/xml"
    return response

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    raw_url = data.get('url', '').strip()
    if not raw_url: return jsonify({"error": "No URL"}), 400

    if not raw_url.startswith(('http://', 'https://')): url = 'https://' + raw_url
    else: url = raw_url

    results = {"score": 0, "logs": [], "details": {}}
    
    try:
        # 1. Unfurl
        try:
            session = requests.Session()
            session.headers.update({'User-Agent': ua.random})
            resp = session.head(url, allow_redirects=True, timeout=5)
            final_url = resp.url
        except:
            final_url = url

        ext = tldextract.extract(final_url)
        root_domain = f"{ext.domain}.{ext.suffix}"
        full_domain = f"{ext.subdomain}.{ext.domain}.{ext.suffix}" if ext.subdomain else root_domain

        # 2. Whitelist Check
        if ext.domain in TRUSTED_GIANTS:
            return jsonify({
                "score": 100, "risk_level": "SAFE",
                "details": {"domain": full_domain, "age": "Verified Brand", "ssl": True, "org": "Global Trust List"},
                "logs": [{"type": "success", "msg": "Verified Trustworthy Brand."}]
            })

        # 3. Data Gathering
        ssl_info = get_ssl_details(full_domain)
        
        # Domain Age
        age_days = None
        try:
            w = whois.whois(root_domain)
            cd = w.creation_date
            if isinstance(cd, list): cd = cd[0]
            if cd: age_days = (datetime.now() - cd).days
        except: pass

        # Content Analysis (Shop Detection)
        is_shop = False
        try:
            r = requests.get(final_url, headers={'User-Agent': ua.random}, timeout=4)
            text = r.text.lower()
            shop_keywords = ['cart', 'basket', 'checkout', 'shipping', 'kosár', 'pénztár', 'szállítás', 'shop', 'store', 'price', 'buy']
            if any(k in text for k in shop_keywords): is_shop = True
        except: pass

        # API Checks
        google_malicious = check_google_api(final_url)
        vt_malicious = check_virustotal_api(final_url)

        # --- 4. NEW LOGIC ENGINE ---
        score = 0
        
        # BASE: If Google/VT say CLEAN, start high (Trust the Authorities)
        if google_malicious is False: 
            score = 60 # Base trust for passing Google check
            results['logs'].append({"type": "success", "msg": "Clean on Google Safe Browsing."})
        elif google_malicious is True:
            score = 0
            results['logs'].append({"type": "danger", "msg": "FLAGGED MALICIOUS BY GOOGLE."})
            # Immediate return for known malware
            return jsonify({"score": 0, "risk_level": "DANGER", "details": {"domain": full_domain}, "logs": results['logs']})
        else:
            score = 40 # Neutral start if no API key

        # SSL
        if ssl_info['valid']:
            score += 10
            if ssl_info['org']: 
                score += 20
                results['logs'].append({"type": "success", "msg": f"Identity Verified: {ssl_info['org']}"})
        else:
            score -= 50
            results['logs'].append({"type": "danger", "msg": "No Secure Connection (HTTPS)."})

        # AGE & GDPR HANDLING
        if age_days:
            results['details']['age'] = f"{age_days} days"
            if age_days > 365: score += 10
            if age_days < 30: 
                score -= 30
                results['logs'].append({"type": "danger", "msg": "Domain is extremely new (< 30 days)."})
        else:
            results['details']['age'] = "Hidden"
            # LOGIC FIX: Don't penalize hidden age if it's a GDPR country (like .eu)
            if ext.suffix in GDPR_TLDS:
                results['logs'].append({"type": "info", "msg": "Domain age hidden (Standard for EU/GDPR)."})
            else:
                score -= 10
                results['logs'].append({"type": "warning", "msg": "Domain age hidden."})

        # SHOP BONUS
        if is_shop:
            score += 10
            results['logs'].append({"type": "success", "msg": "Valid E-commerce structure detected."})

        # CAP SCORE
        score = max(0, min(100, score))
        
        if score >= 75: risk = "SAFE"
        elif score >= 50: risk = "CAUTION"
        else: risk = "DANGER"

        results['score'] = score
        results['risk_level'] = risk
        results['details']['domain'] = full_domain
        results['details']['ssl'] = ssl_info['valid']
        results['details']['ssl_org'] = ssl_info['org'] or "Standard (DV)"

        return jsonify(results)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)