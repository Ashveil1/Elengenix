"""tools/analysis_pipeline.py — Post-finding analysis pipeline.

Extracted from agent_brain.py to break up the monolithic process_query method.
Each analyzer is a separate method, all orchestrated by AnalysisPipeline.run_all().
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from tools.vector_memory import remember
from tools.tool_registry import ToolResult
from tools.mission_state import MissionState, GraphNode, GraphEdge
from tools.governance import Governance, GateDecision
from live_display import display_in_chat_mode

logger = logging.getLogger("elengenix.analysis_pipeline")


class AnalysisPipeline:
    """Runs all post-finding analyzers against tool results.

    Each method corresponds to one analyzer integration that was previously
    inlined in ElengenixAgent.process_query().  Every method follows the
    same ``try:/except: logger.debug()`` pattern so a single analyzer
    failure never breaks the pipeline.
    """

    def __init__(self, agent: Any) -> None:
        self.governance: Governance = agent.governance
        self.payload_mutator: Any = agent.payload_mutator
        self.logic_analyzer: Any = agent.logic_analyzer
        self.activity_logger: Any = agent.activity_logger

    # ── Public entry point ────────────────────────────────────────────────

    def run_all(
        self,
        result: ToolResult,
        tool_name: str,
        target: str,
        step: int,
        mission_key: str,
        mission_state: MissionState,
        callback: Optional[Callable],
    ) -> None:
        """Run every registered analyzer against *result*.

        Each analyzer is called sequentially because later analyzers (e.g.
        ExploitChainBuilder) depend on facts and hypotheses written by
        earlier ones.
        """
        self._run_logic_analysis(result, tool_name, mission_state)
        self._run_bola(result, target, mission_key, mission_state, callback)
        self._run_payload_mutation(result, tool_name, mission_state)
        self._run_waf_evasion(result, target, mission_key, mission_state, callback)
        self._run_smart_recon(result, tool_name, target, mission_key, mission_state, callback)
        self._run_cors(result, mission_state)
        self._run_ssrf(result, mission_state)
        self._persist_vector_memory(result, tool_name, target)
        self._run_soc_analysis(result, tool_name, mission_state)
        self._run_sast(target, mission_key, mission_state, callback)
        self._run_cloud_scan(target, mission_key, mission_state, callback)
        self._run_protocol_analysis(result, tool_name, target, mission_key, mission_state, callback)
        self._run_exploit_chain(target, mission_state)
        self._run_bounty_predictor(result, target, mission_state)

    # ── Analyzers ─────────────────────────────────────────────────────────

    def _run_logic_analysis(
        self,
        result: ToolResult,
        tool_name: str,
        mission_state: MissionState,
    ) -> None:
        try:
            snapshot = mission_state.snapshot(max_items=80)
            hyps = self.logic_analyzer.generate(snapshot, result.findings)
            for h in hyps:
                mission_state.upsert_hypothesis(
                    hyp_id=h.hyp_id,
                    title=h.title,
                    description=h.description,
                    confidence=h.confidence,
                    status="open",
                    tags=h.tags,
                    evidence={"suggested_tests": h.suggested_tests, "tool": tool_name},
                )
        except Exception as e:
            logger.debug(f"BusinessLogicAnalyzer failed: {e}")

    def _run_bola(
        self,
        result: ToolResult,
        target: str,
        mission_key: str,
        mission_state: MissionState,
        callback: Optional[Callable],
    ) -> None:
        try:
            from tools.agent_bola_bridge import AgentBOLABridge, extract_headers_from_mission_state

            headers_a, headers_b = extract_headers_from_mission_state(mission_state.snapshot(max_items=20))
            if not headers_a or not headers_b:
                return

            base_url = target or self._base_url_hint(mission_state)
            bridge = AgentBOLABridge(
                base_url=base_url,
                headers_a=headers_a,
                headers_b=headers_b,
                rate_limit_rps=1.0,
            )
            plan = bridge.propose_plan_from_hypotheses(mission_state.snapshot(max_items=80))
            if not plan:
                return

            bola_gate = self.governance.gate(
                mission_id=mission_key,
                target=target or "global",
                action={
                    "action": "run_bola_differential",
                    "tool": "bola_harness",
                    "command": json.dumps(plan.get("seeds", [])),
                    "purpose": plan.get("description", "BOLA differential test"),
                },
                callback=callback,
            )
            if bola_gate.allowed or (
                bola_gate.decision == "needs_approval"
                and callback
                and callback("Approve BOLA differential test? (yes/no)").lower() in ("y", "yes")
            ):
                if bola_gate.decision == "needs_approval":
                    bola_gate = GateDecision(
                        allowed=True,
                        risk_level=bola_gate.risk_level,
                        decision="allow",
                        rationale="User approved BOLA plan",
                    )
                summary = bridge.execute_plan(mission_state, plan)
                display_in_chat_mode(f"BOLA test complete: {summary.get('findings_count', 0)} findings", "result")
        except Exception as e:
            logger.debug(f"BOLA bridge integration failed: {e}")

    def _run_payload_mutation(
        self,
        result: ToolResult,
        tool_name: str,
        mission_state: MissionState,
    ) -> None:
        try:
            for finding in result.findings:
                if finding.get("type") != "xss":
                    continue
                base_payload = finding.get("payload") or finding.get("evidence")
                if not base_payload or not isinstance(base_payload, str):
                    continue
                muts = self.payload_mutator.mutate(base_payload, max_variants=15)
                if not muts:
                    continue
                mission_state.upsert_hypothesis(
                    hyp_id=f"payload_mutation:xss:{mission_state.target}",
                    title="XSS payload mutation candidates",
                    description="Generated payload variants to test WAF bypass / differential parsing. Not executed automatically.",
                    confidence=0.4,
                    status="open",
                    tags=["payload", "mutation", "xss"],
                    evidence={
                        "base": base_payload,
                        "variants": [{"payload": m.payload, "techniques": m.techniques} for m in muts],
                        "source_tool": tool_name,
                    },
                )
                break
        except Exception as e:
            logger.debug(f"Payload mutation suggestion failed: {e}")

    def _run_waf_evasion(
        self,
        result: ToolResult,
        target: str,
        mission_key: str,
        mission_state: MissionState,
        callback: Optional[Callable],
    ) -> None:
        try:
            for finding in result.findings:
                if finding.get("type") != "xss":
                    continue
                furl = finding.get("url", "")
                if not furl or not (furl.startswith("http://") or furl.startswith("https://")):
                    continue
                base_payload = finding.get("payload") or finding.get("evidence") or "<script>alert(1)</script>"
                if not isinstance(base_payload, str):
                    continue

                waf_gate = self.governance.gate(
                    mission_id=mission_key,
                    target=target or "global",
                    action={
                        "action": "run_waf_evasion",
                        "tool": "waf_evasion",
                        "command": f"test_bypass({furl}, {base_payload[:30]}...)",
                        "purpose": "WAF bypass testing for XSS finding",
                    },
                    callback=callback,
                )
                if not (waf_gate.allowed or waf_gate.decision == "needs_approval"):
                    continue

                from tools.waf_evasion import WAFEvasionEngine

                engine = WAFEvasionEngine(base_url=furl, rate_limit_rps=0.5)
                waf_type, _ = engine.detect_waf(furl, base_payload)
                if waf_type:
                    waf_results = engine.test_bypass(furl, base_payload, waf_type, max_attempts=8)
                    best = engine.get_best_bypass(waf_results)
                    if best and not best.blocked:
                        mission_state.upsert_hypothesis(
                            hyp_id=f"waf_bypass:{furl[:60]}",
                            title="WAF bypass candidate found",
                            description=f"Payload bypassed {waf_type} WAF using {', '.join(best.techniques)}",
                            confidence=best.confidence,
                            status="open",
                            tags=["waf", "bypass", "xss", waf_type],
                            evidence={
                                "url": furl,
                                "waf": waf_type,
                                "payload": best.payload,
                                "techniques": best.techniques,
                                "status_code": best.status_code,
                            },
                        )
                        display_in_chat_mode(
                            f"WAF bypass found for {furl[:60]}... (techniques: {', '.join(best.techniques)})",
                            "result",
                        )
                break
        except Exception as e:
            logger.debug(f"WAF evasion integration failed: {e}")

    def _run_smart_recon(
        self,
        result: ToolResult,
        tool_name: str,
        target: str,
        mission_key: str,
        mission_state: MissionState,
        callback: Optional[Callable],
    ) -> None:
        try:
            domains_found: set = set()
            endpoints_found: set = set()

            for finding in result.findings:
                url = finding.get("url", "")
                if url:
                    try:
                        parsed = urlparse(url)
                        if parsed.netloc:
                            domains_found.add(parsed.netloc)
                        endpoints_found.add(url)
                    except Exception:
                        pass

            for domain in domains_found:
                mission_state.upsert_node(
                    GraphNode(
                        node_id=f"domain:{domain}",
                        node_type="domain",
                        props={"discovered_by": tool_name, "source": "tool_finding"},
                    )
                )
                mission_state.upsert_edge(
                    GraphEdge(
                        edge_id=f"edge:{mission_state.target}:domain:{domain}",
                        src_id=mission_state.target,
                        dst_id=f"domain:{domain}",
                        edge_type="has_domain",
                    )
                )

            for endpoint in list(endpoints_found)[:5]:
                mission_state.add_fact(
                    fact_id=f"endpoint:{tool_name}:{endpoint}",
                    category="endpoint",
                    statement=f"Endpoint discovered: {endpoint}",
                    confidence=0.8,
                    evidence={"tool": tool_name, "endpoint": endpoint},
                )

            if len(domains_found) >= 3 and tool_name in ("subfinder", "httpx"):
                recon_gate = self.governance.gate(
                    mission_id=mission_key,
                    target=target or "global",
                    action={
                        "action": "run_smart_recon",
                        "tool": "smart_recon",
                        "command": f"deep_recon({target})",
                        "purpose": f"Deep asset correlation for {len(domains_found)} discovered domains",
                    },
                    callback=callback,
                )
                if recon_gate.allowed:
                    display_in_chat_mode(f"[Recon] Deep asset correlation available for {len(domains_found)} domains", "info")
        except Exception as e:
            logger.debug(f"Smart recon integration failed: {e}")

    def _run_cors(
        self,
        result: ToolResult,
        mission_state: MissionState,
    ) -> None:
        try:
            from tools.cors_checker import check_cors

            web_endpoints = []
            for finding in result.findings:
                furl = finding.get("url", "")
                if furl and ("http://" in furl or "https://" in furl):
                    web_endpoints.append(furl)
            for endpoint in web_endpoints[:5]:
                cors_result = check_cors(endpoint)
                for issue in cors_result.get("issues", []):
                    mission_state.upsert_hypothesis(
                        hyp_id=f"cors:{endpoint[:60]}",
                        title=f"CORS Misconfiguration: {issue.get('reason', '')}",
                        description=f"Origin tested: {issue.get('origin', '')}. {issue.get('reason', '')}",
                        confidence=0.7 if issue.get("severity") == "high" else 0.5,
                        status="open",
                        tags=["cors", "misconfiguration", issue.get("severity", "medium")],
                        evidence=issue,
                    )
        except Exception as e:
            logger.debug(f"CORS check integration failed: {e}")

    def _run_ssrf(
        self,
        result: ToolResult,
        mission_state: MissionState,
    ) -> None:
        try:
            from tools.ssrf_scanner import SSRFScanner

            for finding in result.findings:
                furl = finding.get("url", "")
                if not furl or not ("http://" in furl or "https://" in furl):
                    continue
                if "?" not in furl:
                    continue
                ssrf_engine = SSRFScanner(base_url=furl, rate_limit_rps=0.5)
                ssrf_findings = ssrf_engine.scan(url=furl)
                for sf in ssrf_findings:
                    mission_state.upsert_hypothesis(
                        hyp_id=f"ssrf:{sf.get('param', '')}:{furl[:50]}",
                        title=sf.get("title", "SSRF Vulnerability"),
                        description=sf.get("description", ""),
                        confidence=sf.get("confidence", 0.5),
                        status="open",
                        tags=["ssrf", sf.get("severity", "high")],
                        evidence=sf,
                    )
                break
        except Exception as e:
            logger.debug(f"SSRF scan integration failed: {e}")

    def _persist_vector_memory(
        self,
        result: ToolResult,
        tool_name: str,
        target: str,
    ) -> None:
        try:
            remember(
                f"Tool {tool_name} executed on {target}: {len(result.findings)} findings. "
                f"Success: {result.success}. Category: {result.category.value}",
                target or "global",
                "tool_result",
                tool=tool_name,
                findings_count=len(result.findings),
                success=result.success,
            )

            for finding in result.findings:
                finding_desc = (
                    f"Finding from {tool_name}: {finding.get('type', 'unknown')} "
                    f"at {finding.get('url', target)} "
                    f"(severity: {finding.get('severity', 'unknown')})"
                )
                remember(
                    finding_desc,
                    target or "global",
                    "finding",
                    tool=tool_name,
                    severity=finding.get("severity", "unknown"),
                    finding_type=finding.get("type", "unknown"),
                    url=finding.get("url", ""),
                )
        except Exception as e:
            logger.debug(f"Vector memory persist failed: {e}")

    def _run_soc_analysis(
        self,
        result: ToolResult,
        tool_name: str,
        mission_state: MissionState,
    ) -> None:
        try:
            from tools.soc_analyzer import SOCAnalyzer
            from tools.threat_intel import ThreatIntelDB, Enricher

            ti_db = ThreatIntelDB()
            analyzer = SOCAnalyzer(ioc_db={})

            for finding in result.findings:
                if finding.get("type") not in ("intrusion", "malware", "recon", "xss", "sqli"):
                    continue

                alert = analyzer.parse_json_alert(
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "source": tool_name,
                        "severity": finding.get("severity", "medium"),
                        "signature": f"{finding.get('type')} detected by {tool_name}",
                        "src_ip": finding.get("src_ip"),
                        "dst_ip": finding.get("dst_ip"),
                        "url": finding.get("url"),
                        "confidence": 0.8 if finding.get("confirmed") else 0.6,
                    },
                    tool_name,
                )

                if alert:
                    enricher = Enricher(ti_db)
                    enriched_finding = enricher.enrich_finding(finding)

                    if enriched_finding.get("threat_intel"):
                        alert.ioc_matches = [
                            ioc["value"]
                            for ioc in enriched_finding["threat_intel"].get("ioc_matches", [])
                        ]

                    rule = analyzer.generate_sigma_rule(alert)
                    if rule:
                        mission_state.upsert_hypothesis(
                            hyp_id=f"detection_rule:{finding.get('type')}:{finding.get('url', '')[:40]}",
                            title=f"Detection rule candidate: {rule.title}",
                            description=f"Auto-generated Sigma rule for {rule.level} severity",
                            confidence=0.7,
                            status="open",
                            tags=["detection_rule", "sigma", finding.get("type", "unknown")],
                            evidence={
                                "rule_title": rule.title,
                                "level": rule.level,
                                "tags": rule.tags,
                                "logsource": rule.logsource,
                                "source_finding": finding,
                            },
                        )
                        display_in_chat_mode(f"[SOC] Detection rule generated for {finding.get('type')} finding", "info")
        except Exception as e:
            logger.debug(f"SOC analyzer integration failed: {e}")

    def _run_sast(
        self,
        target: str,
        mission_key: str,
        mission_state: MissionState,
        callback: Optional[Callable],
    ) -> None:
        try:
            from tools.sast_engine import SASTEngine

            target_path = Path(target or ".")
            if not target_path.exists() or not target_path.is_dir():
                return

            code_extensions = {".py", ".js", ".java", ".go"}
            has_code = any(f.suffix in code_extensions for f in target_path.rglob("*") if f.is_file())
            if not has_code:
                return

            sast_gate = self.governance.gate(
                mission_id=mission_key,
                target=target or "global",
                action={
                    "action": "run_sast",
                    "tool": "sast_engine",
                    "command": f"scan_repository({target})",
                    "purpose": "Static analysis for security vulnerabilities",
                },
                callback=callback,
            )

            if sast_gate.allowed or sast_gate.decision == "needs_approval":
                sast = SASTEngine()
                sast_report = sast.scan_repository(target_path)

                if sast_report.get("total_vulnerabilities", 0) > 0:
                    for vuln in sast_report.get("critical_vulnerabilities", [])[:5]:
                        mission_state.add_fact(
                            fact_id=f"sast:{vuln['id']}",
                            category="vulnerability",
                            statement=f"SAST: {vuln['type']} in {vuln['file']}:{vuln['line']}",
                            confidence=0.8,
                            evidence=vuln,
                        )
                    display_in_chat_mode(f"[SAST] Found {sast_report['total_vulnerabilities']} code vulnerabilities", "warning")
        except Exception as e:
            logger.debug(f"SAST integration failed: {e}")

    def _run_cloud_scan(
        self,
        target: str,
        mission_key: str,
        mission_state: MissionState,
        callback: Optional[Callable],
    ) -> None:
        try:
            from tools.cloud_scanner import CloudScanner

            target_path = Path(target or ".")
            if not target_path.exists() or not target_path.is_dir():
                return

            cloud_files = (
                list(target_path.rglob("*.tf"))
                + list(target_path.rglob("*template*.json"))
                + list(target_path.rglob("*template*.yaml"))
            )
            if not cloud_files:
                return

            cloud_gate = self.governance.gate(
                mission_id=mission_key,
                target=target or "global",
                action={
                    "action": "run_cloud_scan",
                    "tool": "cloud_scanner",
                    "command": f"scan_directory({target})",
                    "purpose": "Cloud security posture assessment",
                },
                callback=callback,
            )

            if cloud_gate.allowed or cloud_gate.decision == "needs_approval":
                cloud_scanner = CloudScanner()
                cloud_report = cloud_scanner.scan_directory(target_path)

                if cloud_report.get("total_findings", 0) > 0:
                    for finding in cloud_report.get("critical_findings", [])[:5]:
                        mission_state.add_fact(
                            fact_id=f"cloud:{finding['id']}",
                            category="misconfiguration",
                            statement=f"Cloud: {finding['type']} in {finding['resource']}",
                            confidence=0.85,
                            evidence=finding,
                        )
                    display_in_chat_mode(f"[Cloud] Found {cloud_report['total_findings']} misconfigurations", "warning")
        except Exception as e:
            logger.debug(f"Cloud scanner integration failed: {e}")

    def _run_protocol_analysis(
        self,
        result: ToolResult,
        tool_name: str,
        target: str,
        mission_key: str,
        mission_state: MissionState,
        callback: Optional[Callable],
    ) -> None:
        try:
            pass

            iot_ports = {1883, 8883, 502, 102, 47808}
            findings_with_ports = [f for f in result.findings if f.get("port") or f.get("url", "")]

            has_iot_port = False
            for finding in findings_with_ports:
                port = finding.get("port", 0)
                url = finding.get("url", "")
                if port in iot_ports or any(f":{p}/" in url for p in iot_ports):
                    has_iot_port = True
                    break

            if has_iot_port:
                proto_gate = self.governance.gate(
                    mission_id=mission_key,
                    target=target or "global",
                    action={
                        "action": "run_protocol_analysis",
                        "tool": "protocol_analyzer",
                        "command": "analyze_iot_protocols",
                        "purpose": "IoT/ICS protocol security analysis",
                    },
                    callback=callback,
                )

                if proto_gate.allowed or proto_gate.decision == "needs_approval":
                    display_in_chat_mode("[Protocol] IoT/ICS protocol detected - consider manual protocol analysis", "info")
                    mission_state.upsert_hypothesis(
                        hyp_id=f"iot_protocol:{target}",
                        title="IoT/ICS Protocol Testing Required",
                        description=f"Non-HTTP ports detected ({iot_ports}). Consider MQTT, Modbus, or gRPC protocol testing.",
                        confidence=0.6,
                        status="open",
                        tags=["iot", "ics", "mqtt", "modbus", "protocol"],
                        evidence={"detected_ports": list(iot_ports), "source": tool_name},
                    )
        except Exception as e:
            logger.debug(f"Protocol analyzer integration failed: {e}")

    def _run_exploit_chain(
        self,
        target: str,
        mission_state: MissionState,
    ) -> None:
        try:
            from tools.exploit_chain_builder import ExploitChainBuilder

            all_facts = mission_state.list_facts(limit=50)

            all_findings = []
            for fact in all_facts:
                all_findings.append({
                    "finding_id": fact.get("fact_id", ""),
                    "type": fact.get("category", "finding"),
                    "severity": fact.get("evidence", {}).get("severity", "medium"),
                    "target": fact.get("statement", "")[:100],
                    "description": fact.get("statement", ""),
                    "confidence": fact.get("confidence", 0.5),
                })

            if len(all_findings) >= 3:
                finding_types = set(f.get("type", "") for f in all_findings)
                if len(finding_types) >= 2:
                    builder = ExploitChainBuilder()
                    builder.process_findings(all_findings)
                    builder.build_chains()
                    high_value = builder.get_high_value_chains(min_probability=0.4)

                    if high_value:
                        top_chain = high_value[0]
                        mission_state.upsert_hypothesis(
                            hyp_id=f"exploit_chain:{target}",
                            title=f"Multi-stage Attack: {top_chain.name}",
                            description=(
                                f"{top_chain.description}. "
                                f"Probability: {top_chain.total_probability:.0%}, "
                                f"Impact: {top_chain.total_impact}"
                            ),
                            confidence=top_chain.total_probability,
                            status="open",
                            tags=["exploit_chain", "multi_stage", top_chain.total_impact],
                            evidence={
                                "chain_id": top_chain.chain_id,
                                "stages": len(top_chain.nodes),
                                "probability": top_chain.total_probability,
                                "impact": top_chain.total_impact,
                                "complexity": top_chain.complexity,
                                "time_estimate": top_chain.time_estimate,
                                "poc_steps": top_chain.poc_steps,
                                "mitigations": top_chain.mitigations,
                            },
                        )
                        display_in_chat_mode(
                            f" Exploit Chain Discovered: {top_chain.name} "
                            f"({len(top_chain.nodes)} stages, {top_chain.total_probability:.0%} success rate)",
                            "critical" if top_chain.total_impact == "critical" else "warning",
                        )

                        if top_chain.total_impact in ("critical", "high"):
                            display_in_chat_mode(
                                " High-value chain detected! Consider submitting as combined impact for increased bounty.",
                                "result",
                            )
        except Exception as e:
            logger.debug(f"Exploit chain analysis failed: {e}")

    def _run_bounty_predictor(
        self,
        result: ToolResult,
        target: str,
        mission_state: MissionState,
    ) -> None:
        try:
            from tools.bounty_predictor import BountyPredictor

            predictor = BountyPredictor()
            high_value_findings = []

            for finding in result.findings:
                pred_finding = {
                    "finding_id": finding.get("finding_id", str(hash(str(finding)))),
                    "type": finding.get("type", "unknown"),
                    "severity": finding.get("severity", "info"),
                    "target": finding.get("target", finding.get("url", "unknown")),
                    "description": finding.get("description", finding.get("evidence", "")),
                    "confidence": finding.get("confidence", 0.5),
                    "cwe_id": finding.get("cwe_id"),
                    "evidence": finding.get("evidence", {}),
                }

                prediction = predictor.predict(pred_finding)

                if prediction.bounty_score >= 70:
                    high_value_findings.append(prediction)
                    mission_state.add_fact(
                        fact_id=f"bounty_predict:{prediction.finding_id}",
                        category="bounty_prediction",
                        statement=f"High bounty potential ({prediction.bounty_score:.0f}/100): {prediction.payout_range}",
                        confidence=prediction.confidence,
                        evidence={
                            "bounty_score": prediction.bounty_score,
                            "payout_range": prediction.payout_range,
                            "triage_speed": prediction.triage_speed,
                            "factors": prediction.factors,
                        },
                    )

            if high_value_findings:
                top = high_value_findings[0]
                display_in_chat_mode(
                    f" Bounty Prediction: {top.bounty_score:.0f}/100 score, est. {top.payout_range} - Submit this first!",
                    "result",
                )

                if top.suggestions:
                    mission_state.upsert_hypothesis(
                        hyp_id=f"bounty_improve:{target}",
                        title=f"Improve bounty potential for {top.finding_id[:40]}",
                        description=f"Current score: {top.bounty_score:.0f}/100. Suggestions: {', '.join(top.suggestions[:3])}",
                        confidence=top.confidence,
                        status="open",
                        tags=["bounty_optimization", "reporting"],
                        evidence={
                            "suggestions": top.suggestions,
                            "report_template": top.report_template[:500],
                            "similar_cves": top.similar_cves,
                        },
                    )
        except Exception as e:
            logger.debug(f"Bounty prediction failed: {e}")

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _base_url_hint(mission_state: MissionState) -> str:
        """Extract a base URL hint from mission state (fallback to http://localhost)."""
        try:
            snap = mission_state.snapshot(max_items=10)
            tgt = snap.get("target", "")
            if tgt and (tgt.startswith("http://") or tgt.startswith("https://")):
                return tgt
            if tgt:
                return f"https://{tgt}"
        except Exception:
            pass
        return "http://localhost"
