import os
import re
import imaplib
import email
import email.header
from email import policy
from email.parser import BytesParser
import json
import threading

from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import joblib
import numpy as np

# ──────────────────────────────────────────
# 0. ENV & CONFIG
# ──────────────────────────────────────────
load_dotenv()
GMAIL_USER = os.getenv("GMAIL_USER", "")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD", "")

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ──────────────────────────────────────────
# 1. LOAD MODELS (Engine 2 & 3)
# ──────────────────────────────────────────
MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")

def safe_load(path):
    """Load a .pkl model if it exists, else return None."""
    full = os.path.join(MODEL_DIR, path)
    if os.path.exists(full):
        try:
            return joblib.load(full)
        except Exception as e:
            print(f"[WARN] Could not load {path}: {e}")
    else:
        print(f"[WARN] Model not found: {full}")
    return None

nlp_vectorizer    = safe_load("nlp_vectorizer.pkl")
nlp_model         = safe_load("phishing_nlp_model.pkl")
url_model         = safe_load("phishing_url_model.pkl")

# ──────────────────────────────────────────
# ENGINE 1 — Header / Heuristics Analysis
# ──────────────────────────────────────────
def analyze_headers(raw_text: str) -> dict:
    """
    Rule-based analysis of email headers.
    Returns a score (0-100) and list of findings.
    """
    score = 0
    findings = []
    raw_lower = raw_text.lower()

    # SPF check
    if "spf=fail" in raw_lower:
        score += 40
        findings.append("SPF: FAIL ❌ — Sender domain not authorized")
    elif "spf=softfail" in raw_lower:
        score += 20
        findings.append("SPF: SOFTFAIL ⚠️ — Sender not explicitly authorized")
    elif "spf=pass" in raw_lower:
        findings.append("SPF: PASS ✅")
    else:
        score += 10
        findings.append("SPF: MISSING ⚠️ — No SPF record found")

    # DKIM check
    if "dkim=fail" in raw_lower or "dkim=none" in raw_lower:
        score += 35
        findings.append("DKIM: FAIL ❌ — Signature invalid or missing")
    elif "dkim=pass" in raw_lower:
        findings.append("DKIM: PASS ✅")
    else:
        score += 15
        findings.append("DKIM: MISSING ⚠️ — No DKIM signature")

    # From domain spoofing check
    from_match = re.search(r'from:\s*[^<]*<([^>]+)>', raw_lower)
    if from_match:
        from_addr = from_match.group(1)
        # Common spoofing: display name says "Google/PayPal/Bank" but domain doesn't match
        spoofed_brands = ["paypal", "google", "amazon", "microsoft", "apple", "bank", "fedex", "irs"]
        for brand in spoofed_brands:
            if brand in raw_lower:
                domain_part = from_addr.split("@")[-1] if "@" in from_addr else ""
                if brand not in domain_part:
                    score += 25
                    findings.append(f"Domain Spoofing: DETECTED ⚠️ — '{brand}' in body but not in sender domain ({domain_part})")
                    break

    # Cap at 100
    score = min(score, 100)
    return {
        "score": score,
        "findings": findings,
        "label": "THREAT" if score >= 40 else ("SUSPICIOUS" if score >= 20 else "SAFE")
    }

# ──────────────────────────────────────────
# ENGINE 2 — NLP Content Analysis
# ──────────────────────────────────────────
def analyze_content(raw_text: str) -> dict:
    """Naive Bayes NLP analysis for phishing keywords/patterns."""
    score = 0
    findings = []
    keywords_found = []

    # Fallback keyword-based if model unavailable
    phishing_keywords = [
        "urgent", "immediately", "verify", "account suspended", "click here",
        "confirm your", "unusual activity", "password reset", "limited time",
        "action required", "your account", "will be closed", "unauthorized",
        "security alert", "verify your identity", "update your", "free gift",
        "congratulations", "winner", "claim your", "invoice", "overdue",
        "payment required"
    ]
    raw_lower = raw_text.lower()
    for kw in phishing_keywords:
        if kw in raw_lower:
            keywords_found.append(kw)

    if nlp_vectorizer and nlp_model:
        try:
            vec = nlp_vectorizer.transform([raw_text])
            proba = nlp_model.predict_proba(vec)[0]
            # Assume class 1 = phishing
            phish_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
            score = int(phish_prob * 100)
            label = "THREAT" if score >= 60 else ("SUSPICIOUS" if score >= 35 else "SAFE")
            findings.append(f"NLP Model confidence: {score}%")
        except Exception as e:
            findings.append(f"NLP model error: {str(e)} — using keyword fallback")
            score = min(len(keywords_found) * 12, 100)
            label = "THREAT" if score >= 60 else ("SUSPICIOUS" if score >= 24 else "SAFE")
    else:
        score = min(len(keywords_found) * 12, 100)
        label = "THREAT" if score >= 60 else ("SUSPICIOUS" if score >= 24 else "SAFE")
        findings.append("NLP model not loaded — keyword heuristics used")

    if keywords_found:
        findings.append(f"Suspicious keywords detected: {', '.join(keywords_found[:8])}")

    return {"score": score, "findings": findings, "keywords": keywords_found, "label": label}

# ──────────────────────────────────────────
# ENGINE 3 — URL XGBoost Analysis
# ──────────────────────────────────────────
def extract_urls(text: str) -> list:
    url_pattern = re.compile(
        r'https?://[^\s<>"\']+|www\.[^\s<>"\']+', re.IGNORECASE
    )
    return url_pattern.findall(text)

def extract_url_features(url: str) -> list:
    """Generate 111 lexical features for a URL."""
    features = []
    parsed_url = url.lower()

    # Basic length features
    features.append(len(url))
    features.append(len(url.split("?")[0]))  # path length
    features.append(url.count("."))
    features.append(url.count("-"))
    features.append(url.count("_"))
    features.append(url.count("/"))
    features.append(url.count("@"))
    features.append(url.count("="))
    features.append(url.count("&"))
    features.append(url.count("%"))
    features.append(url.count("#"))
    features.append(1 if "https" in url else 0)

    # Digit ratio
    digits = sum(c.isdigit() for c in url)
    features.append(digits)
    features.append(digits / max(len(url), 1))

    # Suspicious keywords in URL
    susp_kw = ["login", "verify", "account", "secure", "update", "confirm",
                "password", "bank", "paypal", "ebay", "signin", "webscr",
                "redirect", "free", "click", "download"]
    for kw in susp_kw:
        features.append(1 if kw in parsed_url else 0)

    # TLD suspicion
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
                       ".info", ".ru", ".cn", ".zip", ".click"]
    for tld in suspicious_tlds:
        features.append(1 if url.endswith(tld) else 0)

    # IP-based URL
    ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    features.append(1 if ip_pattern.search(url) else 0)

    # URL shortener
    shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly",
                  "is.gd", "buff.ly", "adf.ly", "short.link"]
    features.append(1 if any(s in url for s in shorteners) else 0)

    # Subdomain count
    try:
        domain_part = url.split("//")[-1].split("/")[0]
        sub_count = domain_part.count(".") - 1
        features.append(max(sub_count, 0))
    except:
        features.append(0)

    # Pad to 111 features
    while len(features) < 111:
        features.append(0)

    return features[:111]

def analyze_urls(raw_text: str) -> dict:
    urls = extract_urls(raw_text)
    results = []
    overall_score = 0

    if not urls:
        return {"score": 0, "findings": ["No URLs found in email"], "urls": [], "label": "SAFE"}

    for url in urls[:10]:  # Analyze max 10 URLs
        url_score = 0
        label = "SAFE"

        if url_model:
            try:
                features = np.array(extract_url_features(url)).reshape(1, -1)
                proba = url_model.predict_proba(features)[0]
                url_score = int(float(proba[1] if len(proba) > 1 else proba[0]) * 100)
                label = "MALICIOUS" if url_score >= 60 else ("SUSPICIOUS" if url_score >= 35 else "SAFE")
            except Exception as e:
                # Fallback heuristic
                url_score = _url_heuristic_score(url)
                label = "MALICIOUS" if url_score >= 60 else ("SUSPICIOUS" if url_score >= 35 else "SAFE")
        else:
            url_score = _url_heuristic_score(url)
            label = "MALICIOUS" if url_score >= 60 else ("SUSPICIOUS" if url_score >= 35 else "SAFE")

        results.append({"url": url[:80], "score": url_score, "label": label})
        overall_score = max(overall_score, url_score)

    findings = [f"{r['url']} → {r['label']} ({r['score']}%)" for r in results]
    if not url_model:
        findings.append("URL model not loaded — heuristic analysis used")

    return {
        "score": overall_score,
        "findings": findings,
        "urls": results,
        "label": "THREAT" if overall_score >= 60 else ("SUSPICIOUS" if overall_score >= 35 else "SAFE")
    }

def _url_heuristic_score(url: str) -> int:
    score = 0
    url_lower = url.lower()
    shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly"]
    if any(s in url_lower for s in shorteners): score += 40
    susp_kw = ["login", "verify", "password", "account", "secure", "update"]
    score += sum(12 for kw in susp_kw if kw in url_lower)
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url): score += 50
    suspicious_tlds = [".tk", ".ml", ".xyz", ".top", ".ru", ".cn", ".click"]
    if any(url_lower.endswith(tld) for tld in suspicious_tlds): score += 35
    return min(score, 100)

# ──────────────────────────────────────────
# THE MASTER DISPATCHER
# ──────────────────────────────────────────
def run_dispatcher(raw_text: str, subject: str = "", sender: str = "") -> dict:
    """
    Parallel-processes the email through all 3 engines.

    Scoring formula (best practice):
      - Engine 1 (Headers): 20% weight
      - Engine 2 (NLP):     55% weight  ← strongest trained signal
      - Engine 3 (URLs):    25% weight  ← with quadratic dampening

    URL Dampening: effective_url = (url_score² / 100)
      Rationale: Borderline URLs (score 35–59) have disproportionately small
      contribution — only clearly malicious URLs (score ≥ 75) fully register.
      This prevents newsletter/tracking URLs from pushing safe emails to SUSPICIOUS.

    Example:
      URL score 45 → dampened to 45²/100 = 20   (reduced impact)
      URL score 80 → dampened to 80²/100 = 64   (still high)
      URL score 95 → dampened to 95²/100 = 90   (confirmed malicious)
    """
    full_text = f"From: {sender}\nSubject: {subject}\n\n{raw_text}"

    results = {}
    errors  = {}

    def run_engine(name, fn, text):
        try:
            results[name] = fn(text)
        except Exception as e:
            errors[name] = str(e)
            results[name] = {"score": 0, "findings": [f"Engine error: {e}"], "label": "SAFE"}

    threads = [
        threading.Thread(target=run_engine, args=("engine1", analyze_headers, full_text)),
        threading.Thread(target=run_engine, args=("engine2", analyze_content, full_text)),
        threading.Thread(target=run_engine, args=("engine3", analyze_urls,   full_text)),
    ]
    for t in threads: t.start()
    for t in threads: t.join()

    e1 = results.get("engine1", {})
    e2 = results.get("engine2", {})
    e3 = results.get("engine3", {})

    raw_url_score = e3.get("score", 0)

    # ── Quadratic URL dampening ──────────────────────────────
    # Low scores contribute very little; high/confirmed scores still register fully.
    damped_url_score = (raw_url_score ** 2) / 100.0

    # ── Weighted combination: Headers=20%, NLP=55%, URL=25% ──
    weighted_score = (
        e1.get("score", 0) * 0.20 +
        e2.get("score", 0) * 0.55 +
        damped_url_score   * 0.25
    )
    final_score = round(weighted_score)

    if final_score >= 60:
        verdict    = "PHISHING"
        risk_level = "HIGH RISK"
    elif final_score >= 35:
        verdict    = "SUSPICIOUS"
        risk_level = "MODERATE RISK"
    else:
        verdict    = "SAFE"
        risk_level = "LOW RISK"

    reasoning_log = []
    reasoning_log.append(f"[DISPATCHER] Formula: (E1×20%) + (E2×55%) + (URL²/100×25%)")
    reasoning_log.append(f"[DISPATCHER] Final weighted score: {final_score}%  →  {verdict}")
    reasoning_log.append(f"[ENGINE 1] Header score: {e1.get('score',0)}%  →  {e1.get('label','N/A')}")
    for f in e1.get("findings", [])[:3]: reasoning_log.append(f"  • {f}")
    reasoning_log.append(f"[ENGINE 2] NLP score: {e2.get('score',0)}%  →  {e2.get('label','N/A')}")
    for f in e2.get("findings", [])[:3]: reasoning_log.append(f"  • {f}")
    reasoning_log.append(f"[ENGINE 3] URL score: {raw_url_score}%  →  dampened to {round(damped_url_score)}%  →  {e3.get('label','N/A')}")
    for f in e3.get("findings", [])[:3]: reasoning_log.append(f"  • {f}")

    return {
        "verdict":       verdict,
        "risk_level":    risk_level,
        "threat_score":  final_score,
        "engine1":       e1,
        "engine2":       e2,
        "engine3":       e3,
        "reasoning_log": reasoning_log,
        "subject":       subject,
        "sender":        sender,
    }


# ──────────────────────────────────────────
# IMAP — Fetch ALL Emails from Gmail (Inbox + Spam)
# ──────────────────────────────────────────

def _parse_email_msg(mail, email_id, folder_label):
    """Fetch and parse a single email by IMAP id. Returns dict or None."""
    try:
        _, msg_data = mail.fetch(email_id, "(RFC822)")
        raw_email = msg_data[0][1]
        msg = BytesParser(policy=policy.default).parsebytes(raw_email)

        subject = str(msg.get("Subject", "No Subject"))
        sender  = str(msg.get("From", "Unknown"))
        msg_id  = str(msg.get("Message-ID", email_id.decode()))
        date    = str(msg.get("Date", ""))

        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        body += part.get_payload(decode=True).decode("utf-8", errors="replace")
                    except Exception:
                        pass
                    break
        else:
            try:
                body = msg.get_payload(decode=True).decode("utf-8", errors="replace")
            except Exception:
                body = str(msg.get_payload())

        raw_headers = ""
        for h, v in msg.items():
            raw_headers += f"{h}: {v}\n"
        raw_headers = raw_headers[:3000]

        return {
            "imap_id": email_id.decode(),
            "msg_id": msg_id,
            "subject": subject,
            "sender": sender,
            "date": date,
            "body": body,
            "raw_headers": raw_headers,
            "folder": folder_label,
        }
    except Exception:
        return None


def _quote_folder(name: str) -> str:
    """Wrap folder name in quotes if it contains spaces or special chars."""
    if any(c in name for c in (' ', '[', ']', '/', '\\', '"')):
        return f'"{name}"'
    return name


def _discover_folders(mail) -> list:
    """
    Use IMAP LIST to discover all available mailbox names.
    Returns list of (folder_name, label) tuples to check.
    Always includes INBOX first, then auto-detects Spam/Junk.
    """
    folders = [("INBOX", "Inbox")]
    spam_added = False

    try:
        _, listing = mail.list()
        for entry in listing:
            if not entry:
                continue
            decoded = entry.decode() if isinstance(entry, bytes) else entry

            # Extract flags and folder name from IMAP LIST response
            # Format: (\Flag1 \Flag2) "/" "Folder Name"
            import re
            m = re.match(r'\(([^)]*)\)\s+"?([^"]+)"?\s+"?(.+?)"?\s*$', decoded)
            if not m:
                continue
            flags_str = m.group(1).lower()
            folder_name = m.group(3).strip().strip('"')

            # Identify spam/junk by IMAP flags or common names
            is_spam = (
                '\\spam' in flags_str or
                '\\junk' in flags_str or
                any(kw in folder_name.lower() for kw in ['spam', 'junk', 'bulk'])
            )

            if is_spam and not spam_added:
                folders.append((folder_name, "Spam"))
                spam_added = True

    except Exception:
        # Fallback if LIST fails: try common Gmail/Outlook names
        for candidate in ["[Gmail]/Spam", "Junk", "Spam", "Bulk Mail"]:
            folders.append((candidate, "Spam"))

    return folders


def fetch_all_emails(max_per_folder: int = 30) -> list:
    """
    Fetches recent emails from INBOX + auto-discovered Spam/Junk folders.
    Returns a list of parsed email dicts (newest first), deduplicated by Message-ID.
    """
    if not GMAIL_USER or not GMAIL_APP_PASSWORD:
        raise ValueError("GMAIL credentials not configured in .env file")

    mail = imaplib.IMAP4_SSL("imap.gmail.com")
    mail.login(GMAIL_USER, GMAIL_APP_PASSWORD)

    folders = _discover_folders(mail)
    all_emails = []
    seen_msg_ids = set()

    for folder_name, folder_label in folders:
        try:
            quoted = _quote_folder(folder_name)
            result, _ = mail.select(quoted, readonly=True)
            if result != "OK":
                continue

            _, search_data = mail.search(None, "ALL")
            ids = search_data[0].split()
            if not ids:
                continue

            recent_ids = ids[-max_per_folder:]   # last N, newest last

            for eid in reversed(recent_ids):     # iterate newest → oldest
                parsed = _parse_email_msg(mail, eid, folder_label)
                if parsed and parsed["msg_id"] not in seen_msg_ids:
                    seen_msg_ids.add(parsed["msg_id"])
                    all_emails.append(parsed)

        except Exception:
            continue   # folder inaccessible — skip silently

    mail.logout()
    return all_emails



# ──────────────────────────────────────────
# API ROUTES
# ──────────────────────────────────────────
@app.route("/api/fetch_live", methods=["POST"])
def fetch_live():
    """
    Fetches ALL emails from INBOX + Spam, runs the dispatcher on each,
    and returns a list of analysis results.
    """
    try:
        emails = fetch_all_emails(max_per_folder=30)

        if not emails:
            return jsonify({"status": "no_new_email", "message": "No emails found"}), 200

        # Run dispatcher on every email in parallel
        results = [None] * len(emails)
        errors  = []

        def analyze_one(idx, em):
            try:
                combined = em["raw_headers"] + "\n\n" + em["body"]
                r = run_dispatcher(combined, em["subject"], em["sender"])
                r["imap_id"] = em["imap_id"]
                r["msg_id"]  = em["msg_id"]
                r["date"]    = em["date"]
                r["folder"]  = em["folder"]
                results[idx] = r
            except Exception as e:
                errors.append(str(e))
                results[idx] = None

        threads = [
            threading.Thread(target=analyze_one, args=(i, em))
            for i, em in enumerate(emails)
        ]
        for t in threads: t.start()
        for t in threads: t.join(timeout=30)

        valid = [r for r in results if r is not None]
        return jsonify({"status": "success", "emails": valid, "count": len(valid)})

    except ValueError as ve:
        return jsonify({"status": "error", "message": str(ve)}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to fetch emails: {str(e)}"}), 500


@app.route("/api/scan_manual", methods=["POST"])
def scan_manual():
    try:
        data = request.get_json(force=True)
        raw_text = data.get("raw_text", "").strip()
        subject  = data.get("subject", "")
        sender   = data.get("sender", "")

        if not raw_text:
            return jsonify({"status": "error", "message": "No email text provided"}), 400

        result = run_dispatcher(raw_text, subject, sender)
        return jsonify({"status": "success", **result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "online",
        "models": {
            "nlp_vectorizer": nlp_vectorizer is not None,
            "nlp_model": nlp_model is not None,
            "url_model": url_model is not None
        },
        "gmail_configured": bool(GMAIL_USER and GMAIL_APP_PASSWORD)
    })


if __name__ == "__main__":
    print("🛡️  PhishGuard Backend starting on http://127.0.0.1:5000")
    print(f"   Gmail configured: {bool(GMAIL_USER and GMAIL_APP_PASSWORD)}")
    print(f"   NLP model loaded: {nlp_model is not None}")
    print(f"   URL model loaded: {url_model is not None}")
    app.run(debug=True, host="0.0.0.0", port=5000)
