"""
PhishGuard Backend Test Suite
Run: cd backend && .\venv\Scripts\python test_backend.py

Tests:
  1. Health check
  2. Manual scan — known phishing email
  3. Manual scan — known safe email
  4. Manual scan — URL-heavy suspicious email
  5. Manual scan — edge case (empty input rejection)
  6. Engine 1 unit — SPF/DKIM failures
  7. Engine 2 unit — NLP phishing keywords
  8. Engine 3 unit — malicious URL detection
"""

import sys
import json
import unittest
import threading

# ── Bootstrap: import app functions directly ───────────────
sys.path.insert(0, ".")
from app import (
    analyze_headers,
    analyze_content,
    analyze_urls,
    run_dispatcher,
    app as flask_app,
)

# ══════════════════════════════════════════════════════════
# TEST DATA
# ══════════════════════════════════════════════════════════

PHISHING_EMAIL = """From: Security Team <no-reply@paypa1.com>
Subject: URGENT: Your account has been suspended
Authentication-Results: spf=fail; dkim=fail;

Dear User,

Our automated systems have flagged a suspicious login attempt.
Please click the link below IMMEDIATELY to verify your identity.

http://paypa1.com/login/verify?token=xGH92kZ
https://bit.ly/3xF2aAbC

Failure to act within 24 hours will result in permanent account suspension.
This is your final warning.
"""

SAFE_EMAIL = """From: IT Department <it@company.com>
Subject: Weekly System Maintenance Schedule
Authentication-Results: spf=pass; dkim=pass;

Hi team,

Please be advised of the upcoming maintenance window this Friday from 11pm-2am.
The following services will be temporarily unavailable:
- Email
- Internal wiki
- VPN access

Contact helpdesk@company.com with any questions.

Best regards,
IT Department
"""

URL_HEAVY_EMAIL = """From: billing@microsft-support.net
Subject: Invoice #94402 Overdue - Action Required
Authentication-Results: spf=softfail;

Your invoice is OVERDUE. Immediate payment required!

Download invoice: http://microsft-support.net/invoice.php?id=94402
Track shipment: https://fedex-delivery.tk/track?id=12345
Reset password: http://192.168.1.105/admin/reset
Claim free gift: https://bit.ly/freeGift123
"""

EMPTY_EMAIL = ""

# ══════════════════════════════════════════════════════════
# UNIT TESTS — Engine 1: Headers
# ══════════════════════════════════════════════════════════

class TestEngine1Headers(unittest.TestCase):

    def test_spf_fail_detected(self):
        result = analyze_headers("Authentication-Results: spf=fail dkim=fail")
        self.assertGreater(result["score"], 30, "SPF fail should raise score above 30")
        self.assertEqual(result["label"], "THREAT")
        spf_findings = [f for f in result["findings"] if "SPF" in f]
        self.assertTrue(len(spf_findings) > 0, "SPF finding should be reported")
        print(f"  ✅ SPF FAIL score: {result['score']} — {result['label']}")

    def test_dkim_fail_detected(self):
        result = analyze_headers("Authentication-Results: spf=pass dkim=fail")
        self.assertIn("DKIM: FAIL", "\n".join(result["findings"]))
        print(f"  ✅ DKIM FAIL detected: {result['findings']}")

    def test_spf_pass_safe(self):
        result = analyze_headers("Authentication-Results: spf=pass dkim=pass")
        self.assertLess(result["score"], 40, "All-pass email should score < 40")
        print(f"  ✅ SPF+DKIM PASS score: {result['score']} — {result['label']}")

    def test_domain_spoofing_paypal(self):
        result = analyze_headers(
            "From: PayPal Support <security@paypa1.com>\nAuthentication-Results: spf=fail"
        )
        self.assertGreater(result["score"], 40)
        print(f"  ✅ Domain spoof PayPal score: {result['score']}")

    def test_softfail_is_suspicious(self):
        result = analyze_headers("Authentication-Results: spf=softfail dkim=pass")
        self.assertGreater(result["score"], 0, "Softfail should have non-zero score")
        print(f"  ✅ SPF SOFTFAIL score: {result['score']}")


# ══════════════════════════════════════════════════════════
# UNIT TESTS — Engine 2: NLP Content
# ══════════════════════════════════════════════════════════

class TestEngine2NLP(unittest.TestCase):

    def test_phishing_keywords_detected(self):
        result = analyze_content(
            "URGENT: Your account has been suspended. Click here immediately to verify!"
        )
        self.assertGreater(result["score"], 20, "Phishing email should score > 20")
        print(f"  ✅ Phishing keywords score: {result['score']} — {result['label']}")
        if result.get("keywords"):
            print(f"     Keywords: {result['keywords'][:5]}")

    def test_safe_content_low_score(self):
        result = analyze_content(
            "Hi team, the meeting is scheduled for Thursday at 2pm. See attached agenda."
        )
        self.assertLess(result["score"], 60, "Safe content should score < 60")
        print(f"  ✅ Safe content score: {result['score']} — {result['label']}")

    def test_financial_threat_detected(self):
        result = analyze_content(
            "Invoice overdue. Immediate payment required. Account will be closed."
        )
        self.assertGreater(result["score"], 20)
        print(f"  ✅ Financial threat score: {result['score']}")

    def test_returns_keywords_list(self):
        result = analyze_content("Urgent: verify your account password now!")
        self.assertIn("keywords", result, "Engine 2 should return keywords list")
        self.assertIn("findings", result, "Engine 2 should return findings")
        print(f"  ✅ Keywords returned: {result.get('keywords', [])}")


# ══════════════════════════════════════════════════════════
# UNIT TESTS — Engine 3: URL XGBoost
# ══════════════════════════════════════════════════════════

class TestEngine3URLs(unittest.TestCase):

    def test_no_urls_returns_safe(self):
        result = analyze_urls("This email has no links whatsoever.")
        self.assertEqual(result["label"], "SAFE")
        self.assertEqual(result["score"], 0)
        print(f"  ✅ No-URL email: {result['label']}")

    def test_malicious_url_detected(self):
        result = analyze_urls(
            "Click here: http://paypa1.com/login/verify?token=abc123"
        )
        self.assertGreater(result["score"], 0, "Suspicious URL should score > 0")
        self.assertTrue(len(result["urls"]) > 0, "Should detect the URL")
        print(f"  ✅ Malicious URL score: {result['score']} — {result['label']}")
        for u in result["urls"]:
            print(f"     {u['url']} → {u['label']} ({u['score']}%)")

    def test_ip_based_url_detected(self):
        result = analyze_urls("Reset here: http://192.168.1.105/admin/reset")
        self.assertGreater(result["score"], 30, "IP-based URL should score high")
        print(f"  ✅ IP-based URL score: {result['score']}")

    def test_url_shortener_flagged(self):
        result = analyze_urls("Download: https://bit.ly/secretLink")
        self.assertGreater(result["score"], 20, "URL shortener should be flagged")
        print(f"  ✅ URL shortener score: {result['score']}")

    def test_suspicious_tld_flagged(self):
        result = analyze_urls("Visit: https://free-gifts.tk/claim")
        self.assertGreater(result["score"], 20, ".tk TLD should be flagged")
        print(f"  ✅ Suspicious TLD (.tk) score: {result['score']}")


# ══════════════════════════════════════════════════════════
# INTEGRATION TESTS — Master Dispatcher
# ══════════════════════════════════════════════════════════

class TestDispatcher(unittest.TestCase):

    def test_phishing_email_high_score(self):
        result = run_dispatcher(PHISHING_EMAIL, "URGENT: suspended", "paypa1.com")
        self.assertGreaterEqual(result["threat_score"], 35,
            f"Phishing email should score >= 35, got {result['threat_score']}")
        self.assertIn(result["verdict"], ["PHISHING", "SUSPICIOUS"])
        print(f"  ✅ Phishing email verdict: {result['verdict']} ({result['threat_score']}%)")

    def test_safe_email_low_score(self):
        result = run_dispatcher(SAFE_EMAIL, "Maintenance Schedule", "it@company.com")
        self.assertLess(result["threat_score"], 60,
            f"Safe email should score < 60, got {result['threat_score']}")
        print(f"  ✅ Safe email verdict: {result['verdict']} ({result['threat_score']}%)")

    def test_url_heavy_email_flagged(self):
        result = run_dispatcher(URL_HEAVY_EMAIL, "Invoice Overdue", "billing@microsft-support.net")
        self.assertGreater(result["threat_score"], 20)
        print(f"  ✅ URL-heavy email verdict: {result['verdict']} ({result['threat_score']}%)")

    def test_result_has_all_keys(self):
        result = run_dispatcher(PHISHING_EMAIL, "Test", "test@test.com")
        required_keys = ["verdict", "risk_level", "threat_score", "engine1", "engine2", "engine3", "reasoning_log"]
        for key in required_keys:
            self.assertIn(key, result, f"Response missing key: {key}")
        print(f"  ✅ All required keys present in dispatcher result")

    def test_reasoning_log_populated(self):
        result = run_dispatcher(PHISHING_EMAIL)
        self.assertTrue(len(result["reasoning_log"]) > 0, "Reasoning log should not be empty")
        print(f"  ✅ Reasoning log has {len(result['reasoning_log'])} entries")
        for line in result["reasoning_log"][:4]:
            print(f"     {line}")


# ══════════════════════════════════════════════════════════
# API INTEGRATION TESTS — Flask Routes
# ══════════════════════════════════════════════════════════

class TestFlaskAPI(unittest.TestCase):

    def setUp(self):
        flask_app.config["TESTING"] = True
        self.client = flask_app.test_client()

    def test_health_endpoint(self):
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertEqual(data["status"], "online")
        print(f"  ✅ /api/health → online")
        print(f"     Models: {data['models']}")

    def test_scan_manual_phishing(self):
        payload = {
            "raw_text": PHISHING_EMAIL,
            "subject": "URGENT: suspended",
            "sender": "no-reply@paypa1.com"
        }
        resp = self.client.post(
            "/api/scan_manual",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertEqual(data["status"], "success")
        self.assertIn("threat_score", data)
        self.assertGreaterEqual(data["threat_score"], 35)
        print(f"  ✅ POST /api/scan_manual (phishing) → {data['verdict']} ({data['threat_score']}%)")

    def test_scan_manual_safe_email(self):
        payload = {
            "raw_text": SAFE_EMAIL,
            "subject": "Maintenance",
            "sender": "it@company.com"
        }
        resp = self.client.post(
            "/api/scan_manual",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertEqual(data["status"], "success")
        print(f"  ✅ POST /api/scan_manual (safe) → {data['verdict']} ({data['threat_score']}%)")

    def test_scan_manual_empty_body(self):
        payload = {"raw_text": "", "subject": "", "sender": ""}
        resp = self.client.post(
            "/api/scan_manual",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(resp.status_code, 400)
        data = json.loads(resp.data)
        self.assertIn("message", data)
        print(f"  ✅ POST /api/scan_manual (empty) → 400 Bad Request ✓")

    def test_scan_manual_returns_all_engines(self):
        payload = {"raw_text": PHISHING_EMAIL, "subject": "Test", "sender": "test@test.com"}
        resp = self.client.post(
            "/api/scan_manual",
            data=json.dumps(payload),
            content_type="application/json"
        )
        data = json.loads(resp.data)
        for engine in ["engine1", "engine2", "engine3"]:
            self.assertIn(engine, data, f"Response must include {engine} result")
            self.assertIn("score", data[engine])
            self.assertIn("label", data[engine])
        print(f"  ✅ All 3 engine results returned in API response")

    def test_scan_url_heavy_email(self):
        payload = {
            "raw_text": URL_HEAVY_EMAIL,
            "subject": "Invoice Overdue",
            "sender": "billing@microsft-support.net"
        }
        resp = self.client.post(
            "/api/scan_manual",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        print(f"  ✅ URL-heavy email → {data['verdict']} ({data['threat_score']}%) — URLs: {len(data.get('engine3',{}).get('urls',[]))}")


# ══════════════════════════════════════════════════════════
# RUNNER
# ══════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n" + "="*60)
    print("  🛡️  PhishGuard Backend Test Suite")
    print("="*60)

    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()

    # Run each class with a header
    test_classes = [
        ("⚙️  Engine 1 — Header / Heuristics", TestEngine1Headers),
        ("🧠  Engine 2 — NLP Content",          TestEngine2NLP),
        ("🔗  Engine 3 — URL XGBoost",          TestEngine3URLs),
        ("🚀  Integration — Master Dispatcher", TestDispatcher),
        ("🌐  API — Flask Routes",              TestFlaskAPI),
    ]

    for label, cls in test_classes:
        print(f"\n{label}")
        print("-" * 50)
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=0, stream=sys.stdout)
    result = runner.run(suite)

    print("\n" + "="*60)
    total = result.testsRun
    passed = total - len(result.failures) - len(result.errors)
    print(f"  Results: {passed}/{total} tests passed")
    if result.failures:
        print(f"  ❌ Failures: {len(result.failures)}")
        for f in result.failures:
            print(f"     {f[0]}: {f[1][:200]}")
    if result.errors:
        print(f"  💥 Errors: {len(result.errors)}")
        for e in result.errors:
            print(f"     {e[0]}: {e[1][:200]}")
    if not result.failures and not result.errors:
        print("  ✅ All tests passed!")
    print("="*60 + "\n")

    sys.exit(0 if result.wasSuccessful() else 1)
