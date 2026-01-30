import ssl
import socket
import whois
import requests
import dns.resolver
import textdistance
import math
import urllib.parse
from flask import Flask, render_template, request, jsonify
from datetime import datetime
from bs4 import BeautifulSoup

app = Flask(__name__)

# --- CONFIGURATION ---
# List of high-value targets often impersonated
PROTECTED_BRANDS = [
    "google", "facebook", "amazon", "apple", "microsoft", "paypal", 
    "netflix", "instagram", "whatsapp", "linkedin", "dropbox", "ebay"
]

def calculate_entropy(string):
    """Calculates randomness of a string. High entropy = potentially auto-generated domain."""
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

def check_mx_records(domain):
    """Checks if the domain has valid Mail Exchange records (Legit businesses usually do)."""
    try:
        dns.resolver.resolve(domain, 'MX')
        return True
    except:
        return False

def check_typosquatting(domain):
    """Checks if domain is suspiciously close to a major brand."""
    domain_base = domain.split('.')[0]
    warnings = []
    
    for brand in PROTECTED_BRANDS:
        if brand in domain_base and domain_base != brand:
            warnings.append(f"Contains brand name '{brand}' but is not official.")
        
        # Jaccard similarity for fuzzy matching
        similarity = textdistance.jaccard(domain_base, brand)
        if 0.6 < similarity < 1.0: # High similarity but not identical
            warnings.append(f"Suspiciously similar to '{brand}' (Typosquatting Risk).")
            
    return warnings

def get_domain_age_detailed(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list): creation_date = creation_date[0]
        
        if not creation_date: return None, "Hidden/Unknown", {}

        now = datetime.now()
        age_days = (now - creation_date).days
        
        # Check registrar (optional: add logic to flag cheap/scammy registrars)
        registrar = w.registrar if w.registrar else "Unknown"
        
        return age_days, creation_date.strftime('%Y-%m-%d'), w
    except:
        return None, "Unknown", {}

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    raw_url = data.get('url', '').strip()
    
    if not raw_url:
        return jsonify({"error": "No URL provided"}), 400

    if not raw_url.startswith(('http://', 'https://')):
        url = 'https://' + raw_url
    else:
        url = raw_url

    results = {
        "score": 0,
        "logs": [],
        "risk_level": "LOW",
        "details": {}
    }
    
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc
        if domain.startswith("www."): domain = domain[4:]

        # 1. SSL/HTTPS Check
        has_ssl = False
        try:
            requests.get(url, timeout=5) # simple connectivity check
            has_ssl = url.startswith("https")
        except:
            results['logs'].append({"type": "danger", "msg": "Site is unreachable or blocking connections."})

        # 2. Domain Age & WHOIS
        age_days, creation_date, whois_data = get_domain_age_detailed(domain)
        
        # 3. MX Records (Email config)
        has_mx = check_mx_records(domain)
        
        # 4. Typosquatting & Brand Safety
        typo_warnings = check_typosquatting(domain)
        
        # 5. Entropy (Randomness)
        entropy = calculate_entropy(domain)
        
        # --- SCORING ENGINE (Max 100) ---
        score = 0
        
        # Base Trust
        if has_ssl: score += 15
        else: results['logs'].append({"type": "danger", "msg": "No SSL Certificate (Not Secure)."})

        if has_mx: score += 15
        else: results['logs'].append({"type": "warning", "msg": "No Email Records (MX) found. Unusual for a real business."})

        # Age Logic (Critical)
        if age_days:
            if age_days > 365*5: score += 30 # > 5 years
            elif age_days > 365: score += 20 # > 1 year
            elif age_days > 180: score += 10 # > 6 months
            else: results['logs'].append({"type": "danger", "msg": f"Domain is very new ({age_days} days). High Risk."})
        else:
            results['logs'].append({"type": "warning", "msg": "Could not verify domain age."})

        # Typosquatting Penalty
        if typo_warnings:
            score -= 30
            for w in typo_warnings: results['logs'].append({"type": "danger", "msg": w})
        else:
            score += 10 # Bonus for clean name

        # Entropy Penalty (e.g. x7f99a.com)
        if entropy > 3.5: # Threshold for randomness
            score -= 15
            results['logs'].append({"type": "warning", "msg": "Domain name looks random/generated."})
        
        # Content Analysis (Scraping)
        try:
            r = requests.get(url, timeout=3)
            soup = BeautifulSoup(r.text, 'html.parser')
            text = soup.get_text().lower()
            
            # Positive Signals
            if "privacy policy" in text or "privacy" in text: score += 10
            if "contact" in text or "support" in text: score += 10
            if "terms" in text: score += 5
            
            # Negative Signals (Scam keywords)
            scam_triggers = ["urgent", "crypto", "bitcoin", "investment", "act now", "lottery"]
            found_triggers = [t for t in scam_triggers if t in text]
            if len(found_triggers) > 2:
                score -= 20
                results['logs'].append({"type": "danger", "msg": f"Detected high-pressure scam keywords: {', '.join(found_triggers)}"})
                
        except:
            results['logs'].append({"type": "warning", "msg": "Could not scan page content (blocked or empty)."})

        # Final Score Normalization
        score = max(0, min(100, score))
        results['score'] = score
        
        if score >= 80: results['risk_level'] = "SAFE"
        elif score >= 50: results['risk_level'] = "CAUTION"
        else: results['risk_level'] = "DANGER"

        results['details'] = {
            "domain": domain,
            "age": f"{age_days} days" if age_days else "Unknown",
            "ssl": has_ssl,
            "mx": has_mx,
            "entropy": round(entropy, 2),
            "registrar": whois_data.get('registrar', 'Unknown')
        }

        return jsonify(results)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)