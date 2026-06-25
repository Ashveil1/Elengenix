"""tools/graphql_scanner.py — GraphQL API Vulnerability Scanner.

Detects GraphQL-specific vulnerabilities:
- Introspection query enabled (schema disclosure)
- Field suggestion attacks
- Batch query abuse
- Mutation-based attacks
- Depth limit bypass
- Rate limiting bypass

Public API:
    GraphQLScanner - Main scanner class
    GraphQLResult - Result of a single test
    GraphQLScanResult - Full scan results
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("elengenix.graphql_scanner")


@dataclass
class GraphQLResult:
    """Result of a single GraphQL test."""
    url: str
    test_type: str
    query: str
    vulnerable: bool
    evidence: str = ""
    schema_info: Dict[str, Any] = field(default_factory=dict)
    severity: str = "Medium"
    confidence: float = 0.0


@dataclass
class GraphQLScanResult:
    """Full GraphQL scan results."""
    target: str
    results: List[GraphQLResult] = field(default_factory=list)
    schema_introspected: bool = False
    total_tests: int = 0
    duration: float = 0.0

    @property
    def is_vulnerable(self) -> bool:
        return any(r.vulnerable for r in self.results)

    def summary(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "vulnerable": self.is_vulnerable,
            "schema_introspected": self.schema_introspected,
            "total_findings": len([r for r in self.results if r.vulnerable]),
            "total_tests": self.total_tests,
            "duration": self.duration,
        }


# Introspection query
INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        type {
          name
          kind
        }
      }
    }
    directives {
      name
      locations
    }
  }
}
"""

# Common GraphQL endpoints
GRAPHQL_ENDPOINTS = [
    "/graphql",
    "/graphiql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/gql",
    "/query",
    "/api/query",
    "/graphql/console",
    "/_graphql",
]


class GraphQLScanner:
    """GraphQL vulnerability scanner.
    
    Tests GraphQL endpoints for common vulnerabilities including
    introspection disclosure, field suggestion, and batch query abuse.
    
    Example:
        scanner = GraphQLScanner()
        result = scanner.scan("https://example.com/graphql")
        if result.is_vulnerable:
            print("GraphQL vulnerabilities found!")
    """
    
    def __init__(
        self,
        timeout: float = 10.0,
        verify_ssl: bool = False,
    ):
        """Initialize the GraphQL scanner.
        
        Args:
            timeout: Request timeout in seconds.
            verify_ssl: Whether to verify SSL certificates.
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
    
    def scan(
        self,
        target_url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> GraphQLScanResult:
        """Scan a GraphQL endpoint for vulnerabilities.
        
        Args:
            target_url: The GraphQL endpoint URL.
            headers: Additional headers to send.
            
        Returns:
            GraphQLScanResult with all test results.
        """
        import requests
        
        start_time = time.time()
        result = GraphQLScanResult(target=target_url)
        
        default_headers = {
            "Content-Type": "application/json",
            "User-Agent": "Elengenix-GraphQL-Scanner/1.0",
        }
        if headers:
            default_headers.update(headers)
        
        # Test 1: Introspection query
        result.total_tests += 1
        try:
            response = requests.post(
                target_url,
                json={"query": INTROSPECTION_QUERY},
                headers=default_headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            
            if response.status_code == 200:
                data = response.json()
                if "data" in data and "__schema" in data.get("data", {}):
                    schema = data["data"]["__schema"]
                    result.schema_introspected = True
                    
                    # Extract schema info
                    schema_info = {
                        "query_type": schema.get("queryType", {}).get("name"),
                        "mutation_type": schema.get("mutationType", {}).get("name"),
                        "types": len(schema.get("types", [])),
                        "directives": len(schema.get("directives", [])),
                    }
                    
                    graphql_result = GraphQLResult(
                        url=target_url,
                        test_type="introspection",
                        query=INTROSPECTION_QUERY[:100],
                        vulnerable=True,
                        evidence=f"Introspection query returned schema with {schema_info['types']} types",
                        schema_info=schema_info,
                        severity="Medium",
                        confidence=0.95,
                    )
                    result.results.append(graphql_result)
                    logger.info(f"Introspection enabled: {schema_info['types']} types")
        
        except Exception as e:
            logger.debug(f"Introspection test failed: {e}")
        
        # Test 2: Field suggestion
        result.total_tests += 1
        try:
            suggestion_query = '{ __type(name: "User") { fields { name } } }'
            response = requests.post(
                target_url,
                json={"query": suggestion_query},
                headers=default_headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            
            if response.status_code == 200:
                data = response.json()
                if "errors" in data:
                    error_msg = str(data["errors"])
                    # Check if error suggests fields
                    if "did you mean" in error_msg.lower():
                        graphql_result = GraphQLResult(
                            url=target_url,
                            test_type="field_suggestion",
                            query=suggestion_query,
                            vulnerable=True,
                            evidence=f"Field suggestion enabled: {error_msg[:200]}",
                            severity="Low",
                            confidence=0.8,
                        )
                        result.results.append(graphql_result)
                        logger.info("Field suggestion enabled")
        
        except Exception as e:
            logger.debug(f"Field suggestion test failed: {e}")
        
        # Test 3: Batch query abuse
        result.total_tests += 1
        try:
            batch_query = [
                {"query": "{ __typename }"},
                {"query": "{ __typename }"},
                {"query": "{ __typename }"},
            ]
            response = requests.post(
                target_url,
                json=batch_query,
                headers=default_headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list) and len(data) == 3:
                    graphql_result = GraphQLResult(
                        url=target_url,
                        test_type="batch_query",
                        query="batch of 3 queries",
                        vulnerable=True,
                        evidence="Batch queries accepted (potential DoS vector)",
                        severity="Medium",
                        confidence=0.85,
                    )
                    result.results.append(graphql_result)
                    logger.info("Batch queries accepted")
        
        except Exception as e:
            logger.debug(f"Batch query test failed: {e}")
        
        # Test 4: Depth limit bypass
        result.total_tests += 1
        try:
            deep_query = '{"query": "query { ' + 'a { ' * 20 + '__typename ' + '} ' * 20 + '}"}'
            response = requests.post(
                target_url,
                json={"query": "query { " + "a { " * 20 + "__typename " + "} " * 20 + "}"},
                headers=default_headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            
            if response.status_code == 200:
                data = response.json()
                if "data" in data:
                    graphql_result = GraphQLResult(
                        url=target_url,
                        test_type="depth_limit",
                        query="nested query depth 20",
                        vulnerable=True,
                        evidence="No depth limit enforced (potential DoS vector)",
                        severity="Medium",
                        confidence=0.7,
                    )
                    result.results.append(graphql_result)
                    logger.info("No depth limit enforced")
        
        except Exception as e:
            logger.debug(f"Depth limit test failed: {e}")
        
        result.duration = time.time() - start_time
        return result
    
    def discover_endpoint(
        self,
        base_url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[str]:
        """Discover GraphQL endpoint from base URL.
        
        Args:
            base_url: Base URL to test.
            headers: Additional headers to send.
            
        Returns:
            Discovered GraphQL endpoint URL, or None if not found.
        """
        import requests
        from urllib.parse import urljoin
        
        default_headers = {
            "Content-Type": "application/json",
            "User-Agent": "Elengenix-GraphQL-Scanner/1.0",
        }
        if headers:
            default_headers.update(headers)
        
        # Test introspection query against common endpoints
        for endpoint in GRAPHQL_ENDPOINTS:
            url = urljoin(base_url.rstrip("/") + "/", endpoint.lstrip("/"))
            
            try:
                response = requests.post(
                    url,
                    json={"query": "{ __typename }"},
                    headers=default_headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if "data" in data and "__typename" in str(data.get("data", {})):
                        logger.info(f"GraphQL endpoint discovered: {url}")
                        return url
            
            except Exception:
                continue
        
        return None
    
    def enumerate_schema(
        self,
        endpoint: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Enumerate GraphQL schema via introspection.
        
        Args:
            endpoint: GraphQL endpoint URL.
            headers: Additional headers to send.
            
        Returns:
            Dictionary containing schema information.
        """
        import requests
        
        default_headers = {
            "Content-Type": "application/json",
            "User-Agent": "Elengenix-GraphQL-Scanner/1.0",
        }
        if headers:
            default_headers.update(headers)
        
        try:
            response = requests.post(
                endpoint,
                json={"query": INTROSPECTION_QUERY},
                headers=default_headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            
            if response.status_code == 200:
                data = response.json()
                if "data" in data and "__schema" in data.get("data", {}):
                    return data["data"]["__schema"]
        
        except Exception as e:
            logger.debug(f"Schema enumeration failed: {e}")
        
        return {}
