"""
test_vuln_engine.py — Tests for Next-Gen Vulnerability Engine.
"""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.vuln_engine import (
    ExploitChain,
    KillChainPhase,
    PayloadGen,
    VulnClass,
    VulnFinding,
    calculate_cvss,
    check_known_cves,
    fingerprint_tech,
    severity_from_cvss,
)


def test_vuln_finding_creation():
    f = VulnFinding(title="SQLi", url="http://x.com/api?id=1", parameter="id")
    assert f.id.startswith("VULN-")
    assert f.cwe == VulnClass.INJECTION.cwe_ids
    assert f.discovered_at > 0
    d = f.to_dict()
    assert d["title"] == "SQLi"
    assert d["cwe"] == VulnClass.INJECTION.cwe_ids
    print("[OK] test_vuln_finding_creation")


def test_payload_generation_sqli():
    p = PayloadGen.for_class(VulnClass.INJECTION)
    assert any("OR" in x.upper() for x in p)
    assert any("SLEEP" in x.upper() for x in p)
    print("[OK] test_payload_generation_sqli")


def test_payload_generation_xss():
    p = PayloadGen.for_class(VulnClass.XSS)
    assert any("<script>" in x for x in p)
    assert any("onerror" in x for x in p)
    print("[OK] test_payload_generation_xss")


def test_payload_generation_ssti_jinja():
    p = PayloadGen.for_class(VulnClass.TEMPLATE_INJECTION, {"tech_stack": "python jinja2"})
    assert any("{{" in x for x in p)
    print("[OK] test_payload_generation_ssti_jinja")


def test_fingerprint_tech_apache():
    headers = {"Server": "Apache/2.4.49"}
    detected = fingerprint_tech(headers, "", "http://x.com")
    techs = [d["tech"] for d in detected]
    assert "Apache" in techs
    print("[OK] test_fingerprint_tech_apache")


def test_fingerprint_tech_wordpress():
    headers = {"X-Powered-By": "PHP/7.4"}
    body = '<meta name="generator" content="WordPress 5.8.1" />'
    detected = fingerprint_tech(headers, body, "http://x.com")
    techs = [d["tech"] for d in detected]
    assert "WordPress" in techs
    print("[OK] test_fingerprint_tech_wordpress")


def test_cve_check_apache():
    cves = check_known_cves("Apache", "2.4.49")
    assert len(cves) == 2
    assert any(c["cve"] == "CVE-2021-42013" for c in cves)
    assert any(c["cvss"] == 9.8 for c in cves)
    print("[OK] test_cve_check_apache (PathJack CVEs detected)")


def test_cve_check_log4shell():
    cves = check_known_cves("Log4j", "2.10.0")
    assert len(cves) >= 1
    assert any(c["cve"] == "CVE-2021-44228" for c in cves)
    assert any(c["cvss"] == 10.0 for c in cves)
    print("[OK] test_cve_check_log4shell (CVSS 10.0 detected)")


def test_cve_check_safe_version():
    cves = check_known_cves("Apache", "2.4.52")
    assert len(cves) == 0
    print("[OK] test_cve_check_safe_version")


def test_cvss_calculation():
    rce = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    score = calculate_cvss(rce)
    assert 9.0 <= score <= 10.0
    assert severity_from_cvss(score) == "Critical"
    print(f"[OK] test_cvss_calculation (RCE: {score} = Critical)")


def test_cvss_calculation_dos():
    dos = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H"
    score = calculate_cvss(dos)
    assert 5.0 <= score <= 7.0
    print(f"[OK] test_cvss_calculation_dos (DoS: {score})")


def test_exploit_chain():
    f1 = VulnFinding(
        title="IDOR", url="http://x.com/api/u/1", parameter="id", vuln_class=VulnClass.BROKEN_ACCESS
    )
    f2 = VulnFinding(
        title="PII Leak",
        url="http://x.com/api/u/1",
        parameter="id",
        vuln_class=VulnClass.SENSITIVE_DATA,
    )
    chain = ExploitChain(name="Account Takeover via IDOR", target="http://x.com")
    chain.add(f1, KillChainPhase.EXPLOIT, "Enumerate user IDs", "Access any user data")
    chain.add(f2, KillChainPhase.ACTIONS, "Extract PII", "GDPR breach, account takeover")
    chain.risk_score = 8.5
    chain.likelihood = 0.9
    chain.total_impact = "Full account takeover of any user"
    rendered = chain.render()
    assert "Account Takeover" in rendered
    assert "ENUMERATE" in rendered.upper() or "Exploit" in rendered
    print("[OK] test_exploit_chain")


if __name__ == "__main__":
    test_vuln_finding_creation()
    test_payload_generation_sqli()
    test_payload_generation_xss()
    test_payload_generation_ssti_jinja()
    test_fingerprint_tech_apache()
    test_fingerprint_tech_wordpress()
    test_cve_check_apache()
    test_cve_check_log4shell()
    test_cve_check_safe_version()
    test_cvss_calculation()
    test_cvss_calculation_dos()
    test_exploit_chain()
    print("\n[OK] All 12 tests passed")
