import os
import ssl
import socket
import whois
import requests
import tldextract
import math
import concurrent.futures
from flask import Flask, render_template, request, jsonify, make_response
from datetime import datetime
from fake_useragent import UserAgent
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
ua = UserAgent()

# --- CONFIGURATION ---
GOOGLE_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")

TRUSTED_GIANTS = {
    "google", "youtube", "facebook", "amazon", "apple", "microsoft", "netflix", 
    "instagram", "linkedin", "ebay", "paypal", "twitter", "x", "wikipedia", 
    "yahoo", "whatsapp", "tiktok", "twitch", "reddit", "pinterest", "zoom", 
    "github", "gitlab", "stackoverflow", "bbc", "cnn", "nytimes", "forbes",
    "arukereso", "emag", "jofogas", "index", "telex", "otpbank", "telekom",
    "simplepay", "szamlazz", "gov", "europa", "antsite"
}

# TLDs where hiding WHOIS is the LAW (GDPR), not a scam tactic.
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

def check_google_api(url):
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
    lines = ["User-agent: *", "Allow: /", "Disallow: /analyze", f"Sitemap: {request.url_root}sitemap.xml"]
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
        # 1. Unfurl Redirects
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
                "details": {"domain": full_domain, "age_display": "Verified Brand", "ssl": True, "org": "Global Trust List"},
                "logs": [{"type": "success", "msg": "Verified Trustworthy Brand."}]
            })

        # 3. Data Gathering
        ssl_info = get_ssl_details(full_domain)
        
        # Domain Age Fetch
        age_days = None
        try:
            w = whois.whois(root_domain)
            cd = w.creation_date
            if isinstance(cd, list): cd = cd[0]
            if cd: age_days = (datetime.now() - cd).days
        except: pass

        # Shop Detection
        is_shop = False
        try:
            r = requests.get(final_url, headers={'User-Agent': ua.random}, timeout=4)
            text = r.text.lower()
            shop_keywords = ['cart', 'basket', 'checkout', 'shipping', 'kosár', 'pénztár', 'szállítás', 'shop', 'store', 'price', 'buy']
            if any(k in text for k in shop_keywords): is_shop = True
        except: pass

        # API Checks
        google_malicious = check_google_api(final_url)
        
        # --- 4. SCORING LOGIC ---
        score = 0
        
        # Base Score (API Trust)
        if google_malicious is False: 
            score = 60
            results['logs'].append({"type": "success", "msg": "Clean on Google Safe Browsing."})
        elif google_malicious is True:
            return jsonify({"score": 0, "risk_level": "DANGER", "details": {"domain": full_domain}, "logs": [{"type": "danger", "msg": "FLAGGED MALICIOUS BY GOOGLE."}]})
        else:
            score = 40 # Neutral start

        # SSL
        if ssl_info['valid']:
            score += 10
            if ssl_info['org']: 
                score += 20
                results['logs'].append({"type": "success", "msg": f"Identity Verified: {ssl_info['org']}"})
        else:
            score -= 50
            results['logs'].append({"type": "danger", "msg": "No Secure Connection (HTTPS)."})

        # --- REFINED AGE LOGIC ---
        # We need to distinguish between "New" (Bad) and "Hidden" (Neutral/Warning)
        
        if age_days is not None:
            # AGE IS VISIBLE
            results['details']['age_display'] = f"{age_days} days"
            
            if age_days < 30:
                score -= 40
                results['logs'].append({"type": "danger", "msg": f"CRITICAL: Domain is very new ({age_days} days). High Risk."})
            elif age_days < 180:
                score -= 10
                results['logs'].append({"type": "warning", "msg": "Domain is less than 6 months old."})
            else:
                score += 10
                results['logs'].append({"type": "success", "msg": "Domain has a long history (> 6 months)."})
        else:
            # AGE IS HIDDEN
            if ext.suffix in GDPR_TLDS:
                # GDPR Case (e.g. .eu, .hu) -> Neutral
                results['details']['age_display'] = "Hidden (GDPR)"
                results['logs'].append({"type": "info", "msg": "Registration date hidden due to GDPR (Normal for EU)."})
                # No score penalty, just info
            else:
                # Suspicious Case (e.g. .com hiding age) -> Warning
                results['details']['age_display'] = "Hidden / Private"
                score -= 15
                results['logs'].append({"type": "warning", "msg": "Registration date is hidden. We cannot verify domain age."})

        # Shop Bonus
        if is_shop: score += 10

        # Final Calc
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