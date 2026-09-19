import os
import re
import requests
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

GSB_API_KEY = os.getenv("GSB_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")


def check_heuristics(url: str) -> dict:
    score = 0
    reasons = []
    SUSPICIOUS_TLDS = {'.zip', '.mov', '.xyz', '.top', '.club', '.tk', '.ml', '.ga', '.cf'}
    URL_SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly'}

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
    except Exception:
        return {"score": 100, "reasons": ["Malformed URL"], "verdict": "Suspicious"}

    if parsed.scheme not in ('http', 'https'):
        score += 20
        reasons.append("Non-standard or missing scheme")
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain.split(':')[0]):
        score += 30
        reasons.append("URL uses raw IP address instead of domain")
    if any(s in domain for s in URL_SHORTENERS):
        score += 15
        reasons.append("Known URL shortener (destination hidden)")
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 20
        reasons.append("Suspicious top-level domain")
    if domain.count('.') >= 4:
        score += 15
        reasons.append("Excessive subdomains (possible spoofing)")
    if '@' in url:
        score += 25
        reasons.append("Contains '@' — classic redirect trick")

    brand_keywords = ['paypal', 'amazon', 'google', 'apple', 'microsoft', 'bank', 'netflix']
    for brand in brand_keywords:
        if brand in domain and not domain.endswith(f"{brand}.com"):
            score += 25
            reasons.append(f"Contains brand keyword '{brand}' but isn't the real domain")
            break

    if len(url) > 100:
        score += 10
        reasons.append("Unusually long URL")
    if any(kw in path for kw in ['login', 'verify', 'secure', 'account', 'update', 'confirm']):
        score += 10
        reasons.append("Path contains urgency/credential-related keywords")

    verdict = "Danger" if score >= 50 else "Suspicious" if score >= 20 else "Safe"
    return {"score": score, "reasons": reasons, "verdict": verdict}


def check_google_safe_browsing(url: str) -> dict:
    if not GSB_API_KEY:
        return {"error": "No GSB API key set"}
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
    payload = {
        "client": {"clientId": "hackathon-scanner", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        resp = requests.post(endpoint, json=payload, timeout=5)
        data = resp.json()
        flagged = "matches" in data and len(data["matches"]) > 0
        return {"flagged": flagged, "raw": data}
    except Exception as e:
        return {"error": str(e)}


def full_scan(url: str) -> dict:
    """Combines all checks into the shared JSON contract."""
    heuristics_result = check_heuristics(url)
    gsb_result = check_google_safe_browsing(url)

    verdict = heuristics_result["verdict"]
    if gsb_result.get("flagged"):
        verdict = "Danger"

    return {
        "url": url,
        "verdict": verdict,
        "score": heuristics_result["score"],
        "sources": {
            "heuristics": heuristics_result,
            "google_safe_browsing": gsb_result,
            "virustotal": None,
            "urlscan": None
        }
    }