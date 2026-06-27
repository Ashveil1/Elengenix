"""
test_multimodal_agent.py — Tests for multi-modal AI agent.
"""

import sys

sys.path.insert(0, "/mnt/data/Elengenix")

from tools.multimodal_agent import (
    ChainOfThoughtReasoner,
    MemoryAugmentedReasoner,
    MemoryTier,
    analyze_code,
    detect_language,
    extract_endpoints,
    extract_secrets,
)


def test_extract_aws_key():
    text = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
    f = extract_secrets(text)
    assert any(s["kind"] == "aws_access_key" for s in f)
    assert any(s["cvss"] == 9.9 for s in f)
    print("[OK] test_extract_aws_key")


def test_extract_github_pat():
    text = "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyzABCDEF"
    f = extract_secrets(text)
    assert any(s["kind"] in ("github_token", "github_pat", "generic_api_key") for s in f)
    print("[OK] test_extract_github_pat")


def test_extract_jwt():
    text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    f = extract_secrets(text)
    assert any(s["kind"] in ("jwt", "bearer_token") for s in f)
    print("[OK] test_extract_jwt")


def test_extract_multiple_secrets():
    text = """
    AWS_KEY=AKIAIOSFODNN7EXAMPLE
    STRIPE_KEY=sk_test_PLACEHOLDER
    password=SuperSecret123
    """
    f = extract_secrets(text)
    assert len(f) >= 3
    print(f"[OK] test_extract_multiple_secrets (found {len(f)} secrets)")


def test_extract_endpoints():
    text = "Visit https://api.example.com or email test@evil.com from 192.168.1.1"
    urls, emails, ips = extract_endpoints(text)
    assert "https://api.example.com" in urls
    assert "test@evil.com" in emails
    assert "192.168.1.1" in ips
    print("[OK] test_extract_endpoints")


def test_code_analyze_eval():
    code = "user_input = input()\nresult = eval(user_input)"
    findings = analyze_code("evil.py", code)
    assert any(f.pattern_id == "dangerous_eval" for f in findings)
    assert any(f.severity == "Critical" for f in findings)
    print("[OK] test_code_analyze_eval")


def test_code_analyze_sql_concat():
    code = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
    findings = analyze_code("db.py", code)
    assert any(f.pattern_id == "sql_string_concat" for f in findings)
    print("[OK] test_code_analyze_sql_concat")


def test_code_analyze_hardcoded_password():
    code = 'password = "SuperSecret123"'
    findings = analyze_code("config.py", code)
    assert any(f.pattern_id == "hardcoded_password" for f in findings)
    print("[OK] test_code_analyze_hardcoded_password")


def test_code_analyze_md5():
    code = "h = hashlib.md5(data).hexdigest()"
    findings = analyze_code("crypto.py", code)
    assert any(f.pattern_id == "weak_crypto" for f in findings)
    print("[OK] test_code_analyze_md5")


def test_code_analyze_pickle():
    code = "data = pickle.loads(request.body)"
    findings = analyze_code("api.py", code)
    assert any(f.pattern_id == "deserialization" for f in findings)
    print("[OK] test_code_analyze_pickle")


def test_detect_languages():
    assert detect_language("a.py") == "python"
    assert detect_language("a.js") == "javascript"
    assert detect_language("a.java") == "java"
    assert detect_language("a.php") == "php"
    assert detect_language("a.txt") == "unknown"
    print("[OK] test_detect_languages")


def test_memory_remember_recall():
    m = MemoryAugmentedReasoner()
    m.remember("Target api.example.com uses Flask 2.0", MemoryTier.WORKING, importance=0.8)
    m.remember("Log4Shell is critical in Java apps", MemoryTier.SEMANTIC, importance=0.9)
    results = m.recall("flask")
    assert len(results) >= 1
    assert "Flask" in results[0].content
    print("[OK] test_memory_remember_recall")


def test_memory_consolidation():
    import time

    m = MemoryAugmentedReasoner()
    item = m.remember("Important finding", MemoryTier.WORKING, importance=0.7)
    item.created_at = time.time() - 7200  # 2 hours ago
    promoted = m.consolidate()
    assert promoted == 1
    assert m.stats()["episodic"] == 1
    assert m.stats()["working"] == 0
    print("[OK] test_memory_consolidation")


def test_chain_of_thought():
    r = ChainOfThoughtReasoner("Investigate possible SQLi")
    r.observe("API returns 200 for all inputs")
    r.hypothesize("Endpoint may use parameterized queries")
    r.test("Send single quote", "Error or 500", "Got 200")
    r.conclude("No SQLi detected")
    rendered = r.render()
    assert "Investigate" in rendered
    assert "OBSERVATION" in rendered.upper()
    assert "HYPOTHESIS" in rendered.upper()
    assert "CONCLUSION" in rendered.upper()
    print("[OK] test_chain_of_thought")


def test_chain_of_thought_verification():
    r = ChainOfThoughtReasoner("Test if vulnerable")
    r.hypothesize("Reflected XSS in search box")
    r.test(
        "Send <script>alert(1)</script>", "Alert or 200 with script", "Got 200 with script in body"
    )
    assert r.hypotheses[-1]["verified"] is True
    print("[OK] test_chain_of_thought_verification")


if __name__ == "__main__":
    test_extract_aws_key()
    test_extract_github_pat()
    test_extract_jwt()
    test_extract_multiple_secrets()
    test_extract_endpoints()
    test_code_analyze_eval()
    test_code_analyze_sql_concat()
    test_code_analyze_hardcoded_password()
    test_code_analyze_md5()
    test_code_analyze_pickle()
    test_detect_languages()
    test_memory_remember_recall()
    test_memory_consolidation()
    test_chain_of_thought()
    test_chain_of_thought_verification()
    print("\n[OK] All 15 tests passed")
