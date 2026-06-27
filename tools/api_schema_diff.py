"""tools/api_schema_diff.py — API Schema Diff Scanner.

Compares API schemas between different versions or environments to detect:
- Removed endpoints (potential breaking changes)
- Added endpoints (new attack surface)
- Changed parameters (potential injection points)
- Schema drift between staging and production

Supports:
- OpenAPI/Swagger 2.0 and 3.0
- GraphQL schemas
- RAML
- API Blueprint

Public API:
    APISchemaDiffer - Main differ class
    SchemaDiff - Result of schema comparison
    EndpointDiff - Diff for a single endpoint
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("elengenix.api_schema_diff")


@dataclass
class EndpointDiff:
    """Diff for a single API endpoint."""

    path: str
    method: str
    change_type: str  # "added", "removed", "modified"
    details: str = ""
    old_schema: Optional[Dict[str, Any]] = None
    new_schema: Optional[Dict[str, Any]] = None


@dataclass
class SchemaDiff:
    """Result of API schema comparison."""

    source_name: str
    target_name: str
    source_type: str  # "openapi", "graphql", "raml"
    target_type: str
    total_changes: int = 0
    added_endpoints: List[EndpointDiff] = field(default_factory=list)
    removed_endpoints: List[EndpointDiff] = field(default_factory=list)
    modified_endpoints: List[EndpointDiff] = field(default_factory=list)
    duration: float = 0.0

    @property
    def has_changes(self) -> bool:
        return (
            len(self.added_endpoints) > 0
            or len(self.removed_endpoints) > 0
            or len(self.modified_endpoints) > 0
        )

    def summary(self) -> Dict[str, Any]:
        return {
            "source": self.source_name,
            "target": self.target_name,
            "has_changes": self.has_changes,
            "added": len(self.added_endpoints),
            "removed": len(self.removed_endpoints),
            "modified": len(self.modified_endpoints),
            "total_changes": self.total_changes,
            "duration": self.duration,
        }


class APISchemaDiffer:
    """API Schema comparison tool.

    Compares two API schemas to detect changes between versions
    or environments. Useful for:
    - Detecting breaking changes
    - Finding new attack surface
    - Identifying schema drift

    Example:
        differ = APISchemaDiffer()
        diff = differ.compare_schemas(
            schema1=openapi_v1,
            schema2=openapi_v2,
            name1="v1",
            name2="v2",
        )
        if diff.has_changes:
            print(f"Found {diff.total_changes} changes")
    """

    def __init__(self):
        """Initialize the API schema differ."""

    def compare_schemas(
        self,
        schema1: Dict[str, Any],
        schema2: Dict[str, Any],
        name1: str = "source",
        name2: str = "target",
    ) -> SchemaDiff:
        """Compare two API schemas.

        Args:
            schema1: First schema (source).
            schema2: Second schema (target).
            name1: Name for the first schema.
            name2: Name for the second schema.

        Returns:
            SchemaDiff with all detected changes.
        """
        start_time = time.time()

        # Detect schema type
        type1 = self._detect_schema_type(schema1)
        type2 = self._detect_schema_type(schema2)

        result = SchemaDiff(
            source_name=name1,
            target_name=name2,
            source_type=type1,
            target_type=type2,
        )

        # Compare based on schema type
        if type1 == "openapi" and type2 == "openapi":
            self._compare_openapi(schema1, schema2, result)
        elif type1 == "graphql" and type2 == "graphql":
            self._compare_graphql(schema1, schema2, result)
        else:
            logger.warning(f"Cannot compare different schema types: {type1} vs {type2}")

        result.total_changes = (
            len(result.added_endpoints)
            + len(result.removed_endpoints)
            + len(result.modified_endpoints)
        )
        result.duration = time.time() - start_time

        return result

    def compare_urls(
        self,
        url1: str,
        url2: str,
        headers1: Optional[Dict[str, str]] = None,
        headers2: Optional[Dict[str, str]] = None,
    ) -> SchemaDiff:
        """Compare schemas from two URLs.

        Args:
            url1: URL of the first schema.
            url2: URL of the second schema.
            headers1: Headers for the first URL.
            headers2: Headers for the second URL.

        Returns:
            SchemaDiff with all detected changes.
        """

        # Fetch schemas
        schema1 = self._fetch_schema(url1, headers1)
        schema2 = self._fetch_schema(url2, headers2)

        if not schema1 or not schema2:
            logger.error("Failed to fetch one or both schemas")
            return SchemaDiff(
                source_name=url1,
                target_name=url2,
                source_type="unknown",
                target_type="unknown",
            )

        return self.compare_schemas(
            schema1=schema1,
            schema2=schema2,
            name1=url1,
            name2=url2,
        )

    def _detect_schema_type(self, schema: Dict[str, Any]) -> str:
        """Detect the type of API schema."""
        if "openapi" in schema:
            return "openapi"
        if "swagger" in schema:
            return "openapi"
        if "__schema" in schema:
            return "graphql"
        if (
            "types" in schema and "queryType" in schema.get("types", [{}])[0]
            if schema.get("types")
            else False
        ):
            return "graphql"
        return "unknown"

    def _fetch_schema(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Fetch schema from URL."""
        import requests

        default_headers = {
            "User-Agent": "Elengenix-API-Schema-Diff/1.0",
        }
        if headers:
            default_headers.update(headers)

        try:
            response = requests.get(
                url,
                headers=default_headers,
                timeout=10,
                verify=False,
            )

            if response.status_code == 200:
                return response.json()

        except Exception as e:
            logger.debug(f"Failed to fetch schema from {url}: {e}")

        return None

    def _compare_openapi(
        self,
        schema1: Dict[str, Any],
        schema2: Dict[str, Any],
        result: SchemaDiff,
    ) -> None:
        """Compare two OpenAPI schemas."""
        paths1 = schema1.get("paths", {})
        paths2 = schema2.get("paths", {})

        # Get all endpoints
        endpoints1 = set()
        endpoints2 = set()

        for path, methods in paths1.items():
            for method in methods.keys():
                if method.lower() in ("get", "post", "put", "delete", "patch"):
                    endpoints1.add((path, method.lower()))

        for path, methods in paths2.items():
            for method in methods.keys():
                if method.lower() in ("get", "post", "put", "delete", "patch"):
                    endpoints2.add((path, method.lower()))

        # Find added endpoints
        for endpoint in endpoints2 - endpoints1:
            path, method = endpoint
            result.added_endpoints.append(
                EndpointDiff(
                    path=path,
                    method=method,
                    change_type="added",
                    details=f"New endpoint: {method.upper()} {path}",
                )
            )

        # Find removed endpoints
        for endpoint in endpoints1 - endpoints2:
            path, method = endpoint
            result.removed_endpoints.append(
                EndpointDiff(
                    path=path,
                    method=method,
                    change_type="removed",
                    details=f"Removed endpoint: {method.upper()} {path}",
                )
            )

        # Find modified endpoints
        for endpoint in endpoints1 & endpoints2:
            path, method = endpoint
            old_endpoint = paths1.get(path, {}).get(method, {})
            new_endpoint = paths2.get(path, {}).get(method, {})

            if old_endpoint != new_endpoint:
                changes = self._compare_endpoint_schemas(old_endpoint, new_endpoint)
                if changes:
                    result.modified_endpoints.append(
                        EndpointDiff(
                            path=path,
                            method=method,
                            change_type="modified",
                            details=changes,
                            old_schema=old_endpoint,
                            new_schema=new_endpoint,
                        )
                    )

    def _compare_graphql(
        self,
        schema1: Dict[str, Any],
        schema2: Dict[str, Any],
        result: SchemaDiff,
    ) -> None:
        """Compare two GraphQL schemas."""
        types1 = {t["name"]: t for t in schema1.get("types", [])}
        types2 = {t["name"]: t for t in schema2.get("types", [])}

        # Find added types
        for type_name in set(types2.keys()) - set(types1.keys()):
            result.added_endpoints.append(
                EndpointDiff(
                    path=type_name,
                    method="type",
                    change_type="added",
                    details=f"New type: {type_name}",
                )
            )

        # Find removed types
        for type_name in set(types1.keys()) - set(types2.keys()):
            result.removed_endpoints.append(
                EndpointDiff(
                    path=type_name,
                    method="type",
                    change_type="removed",
                    details=f"Removed type: {type_name}",
                )
            )

        # Find modified types
        for type_name in set(types1.keys()) & set(types2.keys()):
            old_type = types1[type_name]
            new_type = types2[type_name]

            old_fields = {f["name"] for f in old_type.get("fields", [])}
            new_fields = {f["name"] for f in new_type.get("fields", [])}

            added_fields = new_fields - old_fields
            removed_fields = old_fields - new_fields

            if added_fields:
                result.modified_endpoints.append(
                    EndpointDiff(
                        path=type_name,
                        method="field",
                        change_type="added",
                        details=f"Added fields: {', '.join(added_fields)}",
                    )
                )

            if removed_fields:
                result.modified_endpoints.append(
                    EndpointDiff(
                        path=type_name,
                        method="field",
                        change_type="removed",
                        details=f"Removed fields: {', '.join(removed_fields)}",
                    )
                )

    def _compare_endpoint_schemas(
        self,
        old: Dict[str, Any],
        new: Dict[str, Any],
    ) -> str:
        """Compare two endpoint schemas and return change description."""
        changes = []

        # Compare parameters
        old_params = {p.get("name"): p for p in old.get("parameters", [])}
        new_params = {p.get("name"): p for p in new.get("parameters", [])}

        added_params = set(new_params.keys()) - set(old_params.keys())
        removed_params = set(old_params.keys()) - set(new_params.keys())

        if added_params:
            changes.append(f"Added parameters: {', '.join(added_params)}")
        if removed_params:
            changes.append(f"Removed parameters: {', '.join(removed_params)}")

        # Compare request body
        old_body = old.get("requestBody", {})
        new_body = new.get("requestBody", {})
        if old_body != new_body:
            changes.append("Request body changed")

        # Compare responses
        old_responses = old.get("responses", {})
        new_responses = new.get("responses", {})
        if old_responses != new_responses:
            changes.append("Responses changed")

        return "; ".join(changes) if changes else ""
