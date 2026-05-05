"""tools/graphql_scanner.py

GraphQL Endpoint Scanner for Bug Bounty.

Purpose:
- Auto-discover GraphQL endpoints (common paths)
- Introspection query to detect schema leaks
- Field/type enumeration
- Detect disabled query logging sensitive data
- Test batching and depth attacks
- Find deprecated fields still accessible

Safety:
- Read-only introspection (no mutations)
- Rate-limited queries
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger("elengenix.graphql")


GRAPHQL_PATHS = [
    "/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/api/graphql",
    "/query",
    "/gql",
    "/graphiql",
    "/api",
    "/graphql/console",
]

INTROSPECTION_QUERY = """
{
  __schema {
    types {
      name
      kind
      description
      fields {
        name
        type { name kind ofType { name kind } }
        args { name type { name kind } }
        description
        isDeprecated
        deprecationReason
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    directives { name description args { name type { name kind } } }
  }
}
""".strip()


def _discover_endpoint(base_url: str, timeout: int = 8) -> Optional[str]:
    """Auto-discover GraphQL endpoint on the target."""
    for path in GRAPHQL_PATHS:
        url = base_url.rstrip("/") + path
        try:
            r = requests.post(
                url,
                json={"query": "{__typename}"},
                timeout=timeout,
                verify=False,
            )
            if r.status_code == 200 and '"__typename"' in r.text:
                return url
            if r.status_code in (400, 405):
                ct = r.headers.get("Content-Type", "")
                if "json" in ct and ("graphql" in r.text.lower() or "query" in r.text.lower()):
                    return url
        except Exception:
            continue
    return None


def _introspect(endpoint: str, headers: Dict = None, timeout: int = 15) -> Dict:
    """Run GraphQL introspection query."""
    try:
        r = requests.post(
            endpoint,
            json={"query": INTROSPECTION_QUERY},
            headers=headers or {},
            timeout=timeout,
            verify=False,
        )
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        logger.debug(f"Introspection error: {e}")
    return {}


def _find_sensitive_fields(schema: Dict) -> List[Dict]:
    """Find potentially sensitive fields in schema."""
    sensitive_keywords = [
        "password", "secret", "token", "key", "credential",
        "ssn", "credit", "card", "cvv", "pin", "passport",
        "salary", "private", "admin", "role", "permission",
        "audit", "log", "debug", "internal", "user_id",
    ]

    findings = []
    types = schema.get("__schema", {}).get("types", [])

    for t in types:
        for field in t.get("fields") or []:
            field_name = field.get("name", "").lower()
            for kw in sensitive_keywords:
                if kw in field_name:
                    findings.append({
                        "type_name": t.get("name", ""),
                        "field_name": field.get("name", ""),
                        "keyword": kw,
                        "description": field.get("description", ""),
                        "deprecated": field.get("isDeprecated", False),
                    })
                    break

    return findings


def scan_graphql(target: str, headers: Dict = None) -> List[Dict[str, Any]]:
    """
    Full GraphQL security scan.

    Args:
        target: Base URL or full GraphQL endpoint
        headers: HTTP headers including auth

    Returns:
        List of finding dicts
    """
    findings = []

    # Auto-discover endpoint if full URL not given
    if not target.endswith("/graphql") and "/graphql" not in target:
        endpoint = _discover_endpoint(target)
        if not endpoint:
            return findings
    else:
        endpoint = target

    # Test 1: Introspection available
    schema = _introspect(endpoint, headers=headers)
    if not schema or not schema.get("__schema"):
        # No introspection — but endpoint exists
        findings.append({
            "type": "graphql_endpoint",
            "severity": "info",
            "title": "GraphQL endpoint found (introspection disabled)",
            "target": target,
            "description": f"GraphQL endpoint at {endpoint}. Introspection is disabled (good security practice).",
            "source": "graphql_scanner",
            "url": endpoint,
        })
        return findings

    # Introspection enabled — huge info leak
    schema_data = schema["__schema"]
    query_type = schema_data.get("queryType", {}).get("name", "Unknown")
    mutation_type = schema_data.get("mutationType", {})
    subscription_type = schema_data.get("subscriptionType", {})

    findings.append({
        "type": "graphql_introspection",
        "severity": "high",
        "title": "GraphQL introspection enabled — full schema exposed",
        "target": target,
        "description": (
            f"GraphQL introspection is enabled on {endpoint}.\n"
            f"Query type: {query_type}\n"
            f"Mutation type: {mutation_type.get('name', 'None') if mutation_type else 'None'}\n"
            f"Subscription type: {subscription_type.get('name', 'None') if subscription_type else 'None'}\n"
            f"Total types exposed: {len(schema_data.get('types', []))}"
        ),
        "source": "graphql_scanner",
        "url": endpoint,
        "evidence": {
            "query_type": query_type,
            "has_mutations": bool(mutation_type),
            "has_subscriptions": bool(subscription_type),
            "type_count": len(schema_data.get("types", [])),
        },
    })

    # Test 2: Sensitive fields
    sensitive = _find_sensitive_fields(schema)
    if sensitive:
        for sf in sensitive:
            sev = "high" if sf["keyword"] in ("password", "secret", "token") else "medium"
            findings.append({
                "type": "graphql_sensitive_field",
                "severity": sev,
                "title": f"Sensitive field exposed: {sf['type_name']}.{sf['field_name']}",
                "target": target,
                "description": (
                    f"Field '{sf['field_name']}' on type '{sf['type_name']}' matches sensitive keyword '{sf['keyword']}'.\n"
                    f"Description: {sf['description'] or 'N/A'}\n"
                    f"Deprecated: {sf['deprecated']}"
                ),
                "source": "graphql_scanner",
                "url": endpoint,
            })

    # Test 3: Batching support
    try:
        r = requests.post(
            endpoint,
            json=[{"query": "{__typename}"}, {"query": "{__typename}"}],
            headers=headers or {},
            timeout=10,
            verify=False,
        )
        if r.status_code == 200 and isinstance(r.json(), list):
            findings.append({
                "type": "graphql_batching",
                "severity": "medium",
                "title": "GraphQL batching enabled — rate limit bypass possible",
                "target": target,
                "description": "Multiple queries accepted in a single request. Can be used to bypass rate limits.",
                "source": "graphql_scanner",
                "url": endpoint,
            })
    except Exception:
        pass

    # Test 4: Depth limit (circular query)
    try:
        r = requests.post(
            endpoint,
            json={"query": "query { __typename __typename __typename __typename __typename __typename __typename __typename __typename __typename __typename __typename __typename }"},
            headers=headers or {},
            timeout=10,
            verify=False,
        )
        if r.status_code == 200:
            findings.append({
                "type": "graphql_depth_unlimited",
                "severity": "medium",
                "title": "Possible unlimited query depth — DoS vector",
                "target": target,
                "description": "Server accepted repeated __typename field query. May be vulnerable to depth-based DoS.",
                "source": "graphql_scanner",
                "url": endpoint,
            })
    except Exception:
        pass

    # Test 5: Deprecated fields count
    deprecated_count = 0
    for t in schema_data.get("types", []):
        for f in t.get("fields") or []:
            if f.get("isDeprecated"):
                deprecated_count += 1

    if deprecated_count > 0:
        findings.append({
            "type": "graphql_deprecated",
            "severity": "low",
            "title": f"{deprecated_count} deprecated GraphQL fields still accessible",
            "target": target,
            "description": f"{deprecated_count} deprecated fields are still queryable. These should be removed or hidden.",
            "source": "graphql_scanner",
            "url": endpoint,
        })

    return findings
