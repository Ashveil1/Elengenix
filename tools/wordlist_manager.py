"""
tools/wordlist_manager.py — AI-Driven Smart Wordlist Management (v1.0.0)

Hybrid approach:
- Tier 1: Rule-based wordlists (external files, tech detection)
- Tier 2: AI-driven path generation from context (strategic)
- Tier 3: Dynamic prioritization based on findings

Features:
- External wordlist file management
- Technology stack auto-detection
- AI contextual path generation
- Smart prioritization (bounty potential, previous success)
- Cost-controlled AI calls (budget limit)
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("elengenix.wordlist")


@dataclass
class PathSuggestion:
    """AI-generated path suggestion with metadata."""
    path: str
    confidence: float  # 0.0-1.0
    reasoning: str
    estimated_severity: str  # critical/high/medium/low/info
    bounty_potential: str  # high/medium/low
    source: str  # ai_generated, pattern_expansion, tech_specific


@dataclass
class WordlistConfig:
    """Configuration for wordlist generation."""
    category: str = "default"
    custom_paths: List[str] = field(default_factory=list)
    tech_stack: List[str] = field(default_factory=list)
    max_paths: int = 100
    enable_ai_generation: bool = True
    ai_budget: int = 5  # Max AI calls per scan
    prioritize_bounty: bool = True


class WordlistManager:
    """
    Smart wordlist management with AI augmentation.
    
    Usage:
        wm = WordlistManager()
        paths = wm.get_smart_wordlist(
            config=WordlistConfig(tech_stack=["laravel", "php"]),
            state=agent_state,
            ai_client=ai_client
        )
    """
    
    # Technology to wordlist mapping
    TECH_WORDLISTS = {
        "laravel": ["laravel", "php"],
        "symfony": ["symfony", "php"],
        "django": ["django", "python"],
        "flask": ["flask", "python"],
        "spring": ["spring-boot", "java"],
        "spring-boot": ["spring-boot", "java"],
        "express": ["express", "nodejs"],
        "nextjs": ["nextjs", "nodejs"],
        "wordpress": ["wordpress", "php"],
        "drupal": ["drupal", "php"],
        "graphql": ["graphql"],
        "grpc": ["grpc"],
        "aws": ["aws", "cloud"],
        "gcp": ["gcp", "cloud"],
        "azure": ["azure", "cloud"],
        "kubernetes": ["k8s", "cloud"],
        "docker": ["docker", "cloud"],
    }
    
    # Pattern expansion rules (when AI not available)
    PATTERN_RULES = {
        r"/api/v(\d+)": lambda m: [f"/api/v{int(m.group(1))+i}" for i in range(1, 4)],
        r"/api/(\w+)": lambda m: [f"/api/{m.group(1)}/{sub}" for sub in ["admin", "internal", "v2", "beta"]],
        r"/admin/(\w+)": lambda m: [f"/admin/{m.group(1)}/{sub}" for sub in ["users", "settings", "api", "panel"]],
        r"/v(\d+)": lambda m: [f"/v{int(m.group(1))+i}" for i in range(1, 3)],
    }
    
    # High-value path patterns (bounty potential)
    HIGH_VALUE_PATTERNS = [
        r"/api/.*payment.*",
        r"/api/.*order.*",
        r"/api/.*user.*",
        r"/api/.*admin.*",
        r"/api/.*auth.*",
        r"/admin.*",
        r"/internal.*",
        r"/\.env.*",
        r"/config.*",
        r"/backup.*",
        r"/api/.*export.*",
        r"/api/.*download.*",
    ]
    
    def __init__(self, wordlist_dir: str = "data/wordlists"):
        self.wordlist_dir = Path(wordlist_dir)
        self.wordlist_dir.mkdir(parents=True, exist_ok=True)
        self.ai_calls_made = 0
        self.generated_paths_cache: Set[str] = set()
        
        # Ensure default wordlists exist
        self._ensure_default_wordlists()
    
    def _ensure_default_wordlists(self):
        """Create default wordlist files if they don't exist."""
        defaults = {
            "default.txt": self._get_default_paths(),
            "api-endpoints.txt": self._get_api_paths(),
            "admin-panels.txt": self._get_admin_paths(),
            "sensitive-files.txt": self._get_sensitive_paths(),
            "laravel.txt": self._get_laravel_paths(),
            "spring-boot.txt": self._get_spring_boot_paths(),
            "wordpress.txt": self._get_wordpress_paths(),
            "graphql.txt": self._get_graphql_paths(),
            "auth-bypass.txt": self._get_auth_bypass_paths(),
        }
        
        for filename, paths in defaults.items():
            filepath = self.wordlist_dir / filename
            if not filepath.exists():
                filepath.write_text("\n".join(paths), encoding="utf-8")
                logger.info(f"Created default wordlist: {filepath}")
    
    def get_smart_wordlist(
        self,
        config: WordlistConfig,
        state: Optional[Any] = None,
        ai_client: Optional[Any] = None,
    ) -> List[str]:
        """
        Generate smart wordlist combining rules + AI.
        
        Priority order:
        1. AI-generated contextual paths (if budget allows)
        2. Tech-specific wordlists
        3. Category-based wordlists
        4. Pattern-expanded paths from findings
        5. Default paths
        """
        all_paths: List[str] = []
        path_metadata: Dict[str, Dict] = {}
        
        # 1. AI Contextual Generation (strategic, limited budget)
        if config.enable_ai_generation and ai_client and state:
            ai_paths = self._ai_generate_contextual_paths(
                state, ai_client, config.ai_budget
            )
            for suggestion in ai_paths:
                if suggestion.path not in path_metadata:
                    all_paths.append(suggestion.path)
                    path_metadata[suggestion.path] = {
                        "confidence": suggestion.confidence,
                        "reasoning": suggestion.reasoning,
                        "source": suggestion.source,
                        "bounty_potential": suggestion.bounty_potential,
                    }
        
        # 2. Load tech-specific wordlists
        tech_paths = self._load_tech_wordlists(config.tech_stack)
        for path in tech_paths:
            if path not in path_metadata:
                all_paths.append(path)
                path_metadata[path] = {"source": "tech_specific"}
        
        # 3. Load category wordlist
        category_paths = self._load_wordlist_file(f"{config.category}.txt")
        for path in category_paths:
            if path not in path_metadata:
                all_paths.append(path)
                path_metadata[path] = {"source": "category"}
        
        # 4. Pattern expansion from existing findings
        if state and hasattr(state, 'assets'):
            expanded = self._expand_patterns_from_assets(state.assets)
            for path in expanded:
                if path not in path_metadata:
                    all_paths.append(path)
                    path_metadata[path] = {"source": "pattern_expansion"}
        
        # 5. Custom paths (highest priority - user specified)
        for path in config.custom_paths:
            if path not in path_metadata:
                all_paths.insert(0, path)  # Insert at front
                path_metadata[path] = {"source": "custom"}
        
        # 6. Prioritize
        prioritized = self._prioritize_paths(
            all_paths, path_metadata, config.prioritize_bounty
        )
        
        # Return limited set
        return prioritized[:config.max_paths]
    
    def _ai_generate_contextual_paths(
        self,
        state: Any,
        ai_client: Any,
        budget: int,
    ) -> List[PathSuggestion]:
        """
        Use AI to generate contextual paths based on findings.
        Cost-controlled: only called when high-value findings exist.
        """
        if self.ai_calls_made >= budget:
            return []
        
        # Check if worth using AI
        if not self._should_use_ai(state):
            return []
        
        try:
            # Build context for AI
            context = self._build_ai_context(state)
            
            # Call AI
            from tools.universal_ai_client import AIMessage
            messages = [
                AIMessage(role="system", content=self._get_ai_system_prompt()),
                AIMessage(role="user", content=self._get_ai_user_prompt(context)),
            ]
            
            response = ai_client.chat(messages, temperature=0.3)
            self.ai_calls_made += 1
            
            # Parse response
            return self._parse_ai_response(response.content)
            
        except Exception as e:
            logger.warning(f"AI path generation failed: {e}")
            return []
    
    def _should_use_ai(self, state: Any) -> bool:
        """Determine if AI call is worth the cost."""
        if not hasattr(state, 'findings'):
            return False
        
        # Use AI if:
        # 1. Found high/critical severity
        # 2. Found interesting patterns that could expand
        # 3. Stuck (no new findings for several iterations)
        
        recent_findings = state.findings[-10:] if state.findings else []
        
        for f in recent_findings:
            sev = f.get("severity", "info").lower()
            if sev in ["critical", "high"]:
                return True
            
            # Found API endpoints that could expand
            title = f.get("title", "")
            if any(x in title for x in ["/api/", "/v1/", "/v2/", "/admin/"]):
                return True
        
        return False
    
    def _build_ai_context(self, state: Any) -> Dict:
        """Build context dictionary for AI analysis."""
        assets = getattr(state, 'assets', {})
        findings = getattr(state, 'findings', [])
        
        return {
            "tech_stack": assets.get("tech_stack", []),
            "discovered_endpoints": assets.get("endpoints", [])[:20],
            "discovered_apis": assets.get("api_endpoints", [])[:10],
            "recent_findings": [
                {
                    "title": f.get("title"),
                    "severity": f.get("severity"),
                    "target": f.get("target"),
                    "type": f.get("type"),
                }
                for f in findings[-10:]
            ],
            "auth_status": assets.get("authenticated", False),
            "waf_detected": assets.get("waf_type"),
        }
    
    def _get_ai_system_prompt(self) -> str:
        return """You are an expert penetration tester specializing in API endpoint discovery.
Your task is to generate high-value URL paths based on the discovered context.

Rules:
1. Generate paths that are likely to yield security findings
2. Focus on admin panels, API versions, internal endpoints, and sensitive files
3. Consider the technology stack (Laravel, Spring Boot, etc.)
4. Expand on discovered patterns (if /api/v1 found, suggest /api/v2, /internal/api, etc.)
5. Prioritize paths with high bounty potential

Respond in JSON format only:
{
  "paths": [
    {
      "path": "/api/admin/users",
      "confidence": 0.85,
      "reasoning": "Admin endpoint likely to have IDOR vulnerabilities",
      "estimated_severity": "high",
      "bounty_potential": "high"
    }
  ],
  "strategy_note": "brief explanation of overall approach"
}"""
    
    def _get_ai_user_prompt(self, context: Dict) -> str:
        return f"""Based on the following reconnaissance data, generate 10-15 high-value paths to test:

Technology Stack: {', '.join(context['tech_stack']) or 'Unknown'}

Discovered Endpoints:
{json.dumps(context['discovered_endpoints'], indent=2)}

Recent Findings:
{json.dumps(context['recent_findings'], indent=2)}

Authentication: {'Yes' if context['auth_status'] else 'No'}
WAF Detected: {context['waf_detected'] or 'None'}

Generate paths that:
1. Extend discovered API patterns
2. Target admin/internal functionality  
3. Look for sensitive files and configurations
4. Consider the technology stack

Return JSON only."""
    
    def _parse_ai_response(self, content: str) -> List[PathSuggestion]:
        """Parse AI JSON response into PathSuggestion objects."""
        try:
            # Extract JSON from markdown if needed
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]
            
            data = json.loads(content.strip())
            paths_data = data.get("paths", [])
            
            suggestions = []
            for p in paths_data:
                path = p.get("path", "").strip()
                if not path.startswith("/"):
                    path = "/" + path
                
                suggestions.append(PathSuggestion(
                    path=path,
                    confidence=float(p.get("confidence", 0.5)),
                    reasoning=p.get("reasoning", ""),
                    estimated_severity=p.get("estimated_severity", "medium"),
                    bounty_potential=p.get("bounty_potential", "medium"),
                    source="ai_generated",
                ))
            
            return suggestions
            
        except Exception as e:
            logger.warning(f"Failed to parse AI response: {e}")
            return []
    
    def _load_tech_wordlists(self, tech_stack: List[str]) -> List[str]:
        """Load wordlists based on detected technology."""
        paths: Set[str] = set()
        
        for tech in tech_stack:
            tech_lower = tech.lower()
            if tech_lower in self.TECH_WORDLISTS:
                for wordlist_name in self.TECH_WORDLISTS[tech_lower]:
                    file_paths = self._load_wordlist_file(f"{wordlist_name}.txt")
                    paths.update(file_paths)
        
        return list(paths)
    
    def _load_wordlist_file(self, filename: str) -> List[str]:
        """Load wordlist from file."""
        filepath = self.wordlist_dir / filename
        if not filepath.exists():
            return []
        
        try:
            content = filepath.read_text(encoding="utf-8")
            return [line.strip() for line in content.splitlines() 
                    if line.strip() and not line.startswith("#")]
        except Exception as e:
            logger.warning(f"Failed to load {filename}: {e}")
            return []
    
    def _expand_patterns_from_assets(self, assets: Dict) -> List[str]:
        """Expand paths using pattern rules on discovered endpoints."""
        discovered = assets.get("endpoints", []) + assets.get("api_endpoints", [])
        expanded: Set[str] = set()
        
        for endpoint in discovered:
            for pattern, expander in self.PATTERN_RULES.items():
                match = re.search(pattern, endpoint)
                if match:
                    new_paths = expander(match)
                    expanded.update(new_paths)
        
        return list(expanded)
    
    def _prioritize_paths(
        self, 
        paths: List[str], 
        metadata: Dict[str, Dict],
        prioritize_bounty: bool
    ) -> List[str]:
        """Prioritize paths based on metadata and patterns."""
        def score(path: str) -> float:
            score = 0.0
            meta = metadata.get(path, {})
            
            # AI confidence score
            score += meta.get("confidence", 0.5) * 2.0
            
            # Bounty potential
            if prioritize_bounty:
                bounty = meta.get("bounty_potential", "medium")
                score += {"high": 3.0, "medium": 1.5, "low": 0.5}.get(bounty, 1.0)
                
                # Pattern matching for high-value paths
                for pattern in self.HIGH_VALUE_PATTERNS:
                    if re.search(pattern, path, re.IGNORECASE):
                        score += 2.0
                        break
            
            # Source priority
            source = meta.get("source", "")
            score += {"custom": 3.0, "ai_generated": 2.5, "pattern_expansion": 2.0}.get(source, 1.0)
            
            return score
        
        return sorted(paths, key=score, reverse=True)
    
    def add_custom_wordlist(self, name: str, paths: List[str]):
        """Add user custom wordlist."""
        filepath = self.wordlist_dir / f"{name}.txt"
        filepath.write_text("\n".join(paths), encoding="utf-8")
        logger.info(f"Added custom wordlist: {filepath}")
    
    # Default wordlist content generators
    def _get_default_paths(self) -> List[str]:
        return [
            "/api", "/api/v1", "/api/v2", "/graphql",
            "/admin", "/login", "/register", "/auth",
            "/health", "/status", "/ping",
            "/swagger", "/swagger.json", "/openapi.json",
            "/docs", "/api/docs", "/redoc",
            "/.env", "/config", "/config.json", "/.git/config",
            "/backup", "/backups", "/dump", "/dumps",
            "/api/users", "/api/user", "/api/me", "/api/profile",
            "/api/auth", "/api/token", "/api/login", "/api/register",
            "/api/upload", "/api/files", "/api/export", "/api/download",
            "/api/admin", "/api/internal", "/api/private",
            "/internal", "/private", "/dev", "/staging", "/test",
        ]
    
    def _get_api_paths(self) -> List[str]:
        return [
            "/api", "/api/v1", "/api/v2", "/api/v3", "/api/latest",
            "/api/v1/users", "/api/v1/user", "/api/v1/me",
            "/api/v1/auth", "/api/v1/login", "/api/v1/register",
            "/api/v1/orders", "/api/v1/payments", "/api/v1/invoices",
            "/api/v1/products", "/api/v1/items",
            "/api/v1/admin", "/api/v1/internal", "/api/v1/system",
            "/api/v1/config", "/api/v1/settings",
            "/api/v1/upload", "/api/v1/files", "/api/v1/media",
            "/api/v1/export", "/api/v1/download", "/api/v1/report",
            "/api/v1/search", "/api/v1/query", "/api/v1/lookup",
            "/api/v1/graphql", "/api/v1/subscriptions",
            "/api/v2/users", "/api/v2/auth", "/api/v2/orders",
            "/api/internal", "/api/private", "/api/admin",
            "/api/beta", "/api/staging", "/api/dev",
            "/api/webhooks", "/api/callbacks", "/api/events",
            "/api/notifications", "/api/messages", "/api/emails",
            "/api/integrations", "/api/partners", "/api/vendors",
        ]
    
    def _get_admin_paths(self) -> List[str]:
        return [
            "/admin", "/admin/login", "/admin/auth",
            "/admin/dashboard", "/admin/panel", "/admin/console",
            "/admin/users", "/admin/user", "/admin/accounts",
            "/admin/roles", "/admin/permissions",
            "/admin/settings", "/admin/config", "/admin/configuration",
            "/admin/api", "/admin/api/users", "/admin/api/config",
            "/admin/system", "/admin/status", "/admin/health",
            "/admin/logs", "/admin/audit", "/admin/history",
            "/admin/backup", "/admin/export", "/admin/import",
            "/admin/database", "/admin/db", "/admin/sql",
            "/admin/superuser", "/admin/root", "/admin/sudo",
            "/administrator", "/administrator/login",
            "/manage", "/management", "/manager",
            "/cp", "/controlpanel", "/control-panel",
            "/moderator", "/mod", "/staff",
        ]
    
    def _get_sensitive_paths(self) -> List[str]:
        return [
            "/.env", "/.env.local", "/.env.production", "/.env.dev",
            "/.env.backup", "/env.txt", "/environment",
            "/config.json", "/config.yaml", "/config.yml",
            "/config.php", "/config.inc", "/config.ini",
            "/.config", "/config/config.json", "/app/config",
            "/.git/config", "/.git/HEAD", "/.gitignore",
            "/.github", "/.gitlab-ci.yml",
            "/docker-compose.yml", "/Dockerfile",
            "/.htaccess", "/.htpasswd",
            "/robots.txt", "/sitemap.xml",
            "/backup", "/backups", "/backup.zip", "/backup.tar.gz",
            "/dump", "/dumps", "/sql", "/database.sql",
            "/api/.env", "/admin/.env", "/app/.env",
            "/test", "/testing", "/dev", "/development",
            "/debug", "/.debug", "/phpinfo.php", "/info.php",
            "/status", "/server-status", "/health", "/ready",
            "/metrics", "/prometheus", "/actuator", "/actuator/env",
            "/swagger-ui.html", "/swagger-ui", "/api/swagger",
            "/console", "/_debug", "/debug toolbar",
        ]
    
    def _get_laravel_paths(self) -> List[str]:
        return [
            "/artisan", "/horizon", "/telescope",
            "/_debugbar", "/debugbar",
            "/vendor/phpunit", "/vendor/autoload.php",
            "/storage/logs", "/storage/app", "/storage/debugbar",
            "/bootstrap/cache", "/bootstrap/app.php",
            "/config/app.php", "/config/database.php",
            "/routes/web.php", "/routes/api.php",
            "/.env", "/.env.example",
            "/public/hot", "/public/storage",
            "/api/v1", "/api/user", "/api/auth",
            "/admin", "/admin/dashboard",
        ]
    
    def _get_spring_boot_paths(self) -> List[str]:
        return [
            "/actuator", "/actuator/health", "/actuator/info",
            "/actuator/env", "/actuator/configprops",
            "/actuator/metrics", "/actuator/loggers",
            "/actuator/threaddump", "/actuator/heapdump",
            "/actuator/httptrace", "/actuator/mappings",
            "/actuator/auditevents", "/actuator/conditions",
            "/actuator/beans", "/actuator/caches",
            "/actuator/integrationgraph", "/actuator/scheduledtasks",
            "/actuator/jolokia", "/actuator/hystrix.stream",
            "/admin", "/admin/health", "/admin/dashboard",
            "/metrics", "/prometheus", "/health", "/info",
            "/env", "/trace", "/dump", "/logfile",
            "/api/v1", "/api/v2", "/api/actuator",
            "/swagger-ui.html", "/swagger-ui", "/swagger",
            "/v2/api-docs", "/v3/api-docs",
            "/api/swagger-ui.html", "/api/v2/api-docs",
        ]
    
    def _get_wordpress_paths(self) -> List[str]:
        return [
            "/wp-admin", "/wp-admin/login.php",
            "/wp-admin/admin-ajax.php", "/wp-admin/admin-post.php",
            "/wp-login.php", "/wp-logout.php",
            "/wp-content", "/wp-content/uploads",
            "/wp-content/plugins", "/wp-content/themes",
            "/wp-includes", "/wp-json", "/wp-json/wp/v2",
            "/wp-json/wp/v2/users", "/wp-json/wp/v2/posts",
            "/wp-json/wp/v2/pages", "/wp-json/wp/v2/media",
            "/xmlrpc.php", "/wp-config.php",
            "/.htaccess", "/robots.txt",
            "/sitemap.xml", "/sitemap_index.xml",
            "/wp-admin/install.php", "/wp-admin/setup-config.php",
            "/wp-admin/maint/repair.php",
        ]
    
    def _get_graphql_paths(self) -> List[str]:
        return [
            "/graphql", "/graphiql", "/graphql/console",
            "/api/graphql", "/api/v1/graphql", "/api/v2/graphql",
            "/graphql/v1", "/graphql/v2",
            "/query", "/api/query", "/gql",
            "/graphql/schema", "/graphql/introspection",
            "/graphql/explorer", "/graphql/playground",
            "/playground", "/altair", "/ voyager",
            "/graphql.json", "/graphql.yaml",
            "/.well-known/graphql",
        ]
    
    def _get_auth_bypass_paths(self) -> List[str]:
        return [
            "/admin", "/admin/login", "/admin/auth",
            "/api/admin", "/api/internal", "/api/system",
            "/internal", "/private", "/restricted",
            "/api/v1/admin", "/api/v2/admin",
            "/api/v1/internal", "/api/v2/internal",
            "/api/users", "/api/user/list", "/api/user/all",
            "/api/accounts", "/api/account/list",
            "/api/config", "/api/settings", "/api/secrets",
            "/debug", "/test", "/dev", "/staging",
            "/api/debug", "/api/test", "/api/dev",
            "/_api", "/_internal", "/_admin",
            "/api/", "/api//", "/api/admin/",
        ]


# Convenience function for quick usage
def get_smart_wordlist(
    tech_stack: List[str] = None,
    custom_paths: List[str] = None,
    state: Any = None,
    ai_client: Any = None,
    max_paths: int = 100,
) -> List[str]:
    """Quick function to get smart wordlist."""
    wm = WordlistManager()
    config = WordlistConfig(
        tech_stack=tech_stack or [],
        custom_paths=custom_paths or [],
        max_paths=max_paths,
    )
    return wm.get_smart_wordlist(config, state, ai_client)
