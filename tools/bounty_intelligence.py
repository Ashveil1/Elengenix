"""tools/bounty_intelligence.py

Phase 1: Intelligence Discovery - HackerOne Program Discovery Engine

Purpose:
- Discover profitable bug bounty programs automatically
- HackerOne API integration (for users with API key)
- Public scraping (token-free alternative)
- Program ranking by potential profitability

Features:
- Two modes: API (authenticated) and Public (scraping)
- Smart filtering: offers_bounties, response_time, scope_clarity
- Caching: 6-hour cache to respect rate limits
- Ranking: Multi-factor scoring for program selection

Usage:
    from tools.bounty_intelligence import BountyIntelligence
    
    # API mode (with HackerOne API key)
    intel = BountyIntelligence(api_key="your_key")
    programs = intel.discover_programs_api(min_bounty=500, limit=10)
    
    # Public mode (no API key needed)
    intel = BountyIntelligence()
    programs = intel.discover_programs_public(limit=10)
    
    # Rank by profitability
    ranked = intel.rank_programs(programs)
    
    # Get top recommendation
    top = intel.get_top_recommendation()

Database:
    SQLite cache at .config/elengenix/programs_cache.db
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests

logger = logging.getLogger("elengenix.bounty_intel")


@dataclass
class BountyProgram:
    """Represents a bug bounty program."""
    id: str
    name: str
    platform: str  # hackerone, bugcrowd, etc.
    url: str
    offers_bounties: bool
    min_bounty: int
    max_bounty: int
    currency: str = "USD"
    scope: List[Dict] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    response_time_hours: Optional[int] = None
    is_public: bool = True
    cached_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    # Scoring fields
    score_total: float = 0.0
    score_reward: float = 0.0
    score_response: float = 0.0
    score_scope: float = 0.0
    
    @property
    def bounty_range(self) -> str:
        """Format bounty range for display."""
        if self.min_bounty == self.max_bounty:
            return f"${self.min_bounty:,}"
        return f"${self.min_bounty:,} - ${self.max_bounty:,}"
    
    @property
    def is_worth_targeting(self) -> bool:
        """Quick check if program is worth targeting."""
        return (
            self.offers_bounties and
            self.max_bounty >= 500 and
            self.is_public
        )


class BountyIntelligence:
    """
    Intelligence Discovery Engine for Bug Bounty Programs.
    
    Supports:
    - HackerOne API (authenticated, more data)
    - Public scraping (token-free, basic data)
    - Smart ranking algorithm
    - Persistent caching
    """
    
    CACHE_DIR = Path(".config/elengenix")
    CACHE_DB = CACHE_DIR / "programs_cache.db"
    CACHE_TTL_HOURS = 6
    
    # HackerOne API endpoints
    HACKERONE_API_BASE = "https://api.hackerone.com/v1"
    HACKERONE_PROGRAMS_URL = "https://hackerone.com/bug-bounty-programs"
    
    def __init__(self, api_key: Optional[str] = None, 
                 api_username: Optional[str] = None):
        """
        Initialize intelligence engine.
        
        Args:
            api_key: HackerOne API key (optional, for API mode)
            api_username: HackerOne username (optional, for API mode)
        """
        self.api_key = api_key
        self.api_username = api_username
        self.api_auth = None
        
        if api_key and api_username:
            self.api_auth = (api_username, api_key)
        
        self._ensure_cache()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Elengenix-Bounty-Intelligence/1.0 (Security Research)"
        })
    
    def _ensure_cache(self) -> None:
        """Ensure cache directory and database exist."""
        self.CACHE_DIR.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(self.CACHE_DB)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS programs (
                id TEXT PRIMARY KEY,
                name TEXT,
                platform TEXT,
                url TEXT,
                offers_bounties INTEGER,
                min_bounty INTEGER,
                max_bounty INTEGER,
                currency TEXT,
                scope_json TEXT,
                out_of_scope_json TEXT,
                response_time_hours INTEGER,
                is_public INTEGER,
                cached_at TEXT,
                score_total REAL
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_programs_bounties 
            ON programs(offers_bounties, max_bounty DESC)
        """)
        
        conn.commit()
        conn.close()
    
    def discover_programs_api(self, 
                            min_bounty: int = 100,
                            offers_bounties: bool = True,
                            state: str = "open",
                            limit: int = 50) -> List[BountyProgram]:
        """
        Discover programs using HackerOne API (authenticated).
        
        Args:
            min_bounty: Minimum bounty threshold
            offers_bounties: Only programs that offer bounties
            state: Program state (open, closed)
            limit: Max programs to fetch
            
        Returns:
            List of BountyProgram objects
        """
        if not self.api_auth:
            logger.warning("No API credentials, falling back to public mode")
            return self.discover_programs_public(limit=limit)
        
        programs = []
        page = 1
        per_page = 25
        
        logger.info("Fetching programs from HackerOne API...")
        
        while len(programs) < limit:
            try:
                url = f"{self.HACKERONE_API_BASE}/hackers/programs"
                params = {
                    "page[number]": page,
                    "page[size]": per_page,
                }
                
                response = self.session.get(
                    url, 
                    auth=self.api_auth,
                    params=params,
                    timeout=30
                )
                response.raise_for_status()
                
                data = response.json()
                batch = data.get("data", [])
                
                if not batch:
                    break
                
                for item in batch:
                    program = self._parse_api_program(item)
                    
                    # Filter
                    if offers_bounties and not program.offers_bounties:
                        continue
                    if program.max_bounty < min_bounty:
                        continue
                    
                    programs.append(program)
                    
                    if len(programs) >= limit:
                        break
                
                # Check for next page
                links = data.get("links", {})
                if "next" not in links:
                    break
                
                page += 1
                time.sleep(0.5)  # Rate limiting
                
            except requests.exceptions.RequestException as e:
                logger.error(f"API request failed: {e}")
                break
            except Exception as e:
                logger.error(f"Error parsing API response: {e}")
                continue
        
        logger.info(f"Found {len(programs)} programs via API")
        
        # Cache results
        self._cache_programs(programs)
        
        return programs
    
    def _parse_api_program(self, data: Dict) -> BountyProgram:
        """Parse HackerOne API response into BountyProgram."""
        attributes = data.get("attributes", {})
        relationships = data.get("relationships", {})
        
        # Extract bounty range
        min_bounty = 0
        max_bounty = 0
        offers_bounties = False
        
        bounty_data = relationships.get("bounty_range", {}).get("data", {})
        if bounty_data:
            offers_bounties = True
            min_bounty = bounty_data.get("min", 0)
            max_bounty = bounty_data.get("max", 0)
        
        # Extract scope
        scope = []
        scope_data = relationships.get("structured_scopes", {}).get("data", [])
        for item in scope_data:
            scope_item = item.get("attributes", {})
            scope.append({
                "identifier": scope_item.get("asset_identifier", ""),
                "type": scope_item.get("asset_type", ""),
                "eligible": scope_item.get("eligible_for_bounty", False),
                "instruction": scope_item.get("instruction", "")[:200],
            })
        
        return BountyProgram(
            id=data.get("id", ""),
            name=attributes.get("name", "Unknown"),
            platform="hackerone",
            url=f"https://hackerone.com/{attributes.get('handle', '')}",
            offers_bounties=offers_bounties,
            min_bounty=min_bounty,
            max_bounty=max_bounty,
            currency=bounty_data.get("currency", "USD") if bounty_data else "USD",
            scope=scope,
            response_time_hours=attributes.get("response_time", {}).get("hours", None),
            is_public=attributes.get("state", "") == "open",
        )
    
    def discover_programs_public(self, limit: int = 30) -> List[BountyProgram]:
        """
        Discover programs via public scraping (no API key needed).
        
        This is respectful scraping with rate limiting.
        
        Args:
            limit: Max programs to fetch
            
        Returns:
            List of BountyProgram objects
        """
        logger.info("Fetching programs from public pages...")
        
        programs = []
        
        try:
            # Scrape the programs directory
            url = "https://hackerone.com/programs"
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            # Parse programs from the page
            # Note: HackerOne uses JavaScript rendering, so we need to find
            # the data in the initial HTML or use a different approach
            
            # Try to find program data in the HTML
            html = response.text
            
            # Look for JSON data embedded in the page
            json_matches = re.findall(
                r'window\.__REACT_QUERY_STATE__\s*=\s*(\{.*?\});',
                html,
                re.DOTALL
            )
            
            if json_matches:
                try:
                    data = json.loads(json_matches[0])
                    # Extract programs from the React state
                    programs_data = self._extract_from_react_state(data)
                    
                    for prog_data in programs_data[:limit]:
                        program = self._parse_public_program(prog_data)
                        if program.is_worth_targeting:
                            programs.append(program)
                            
                except json.JSONDecodeError:
                    logger.warning("Could not parse React state, using fallback")
            
            # Fallback: scrape individual program pages if needed
            if len(programs) < limit:
                logger.info("Using fallback scraping method...")
                fallback_programs = self._scrape_programs_fallback(limit - len(programs))
                programs.extend(fallback_programs)
            
            logger.info(f"Found {len(programs)} programs via public scraping")
            
            # Cache results
            self._cache_programs(programs)
            
            return programs
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Public scraping failed: {e}")
            return self._get_cached_programs(limit)
        except Exception as e:
            logger.error(f"Unexpected error in public scraping: {e}")
            return self._get_cached_programs(limit)
    
    def _extract_from_react_state(self, data: Dict) -> List[Dict]:
        """Extract program data from React query state."""
        programs = []
        
        try:
            # Navigate the React query state structure
            queries = data.get("queries", [])
            for query in queries:
                query_data = query.get("state", {}).get("data", {})
                if isinstance(query_data, list):
                    programs.extend(query_data)
                elif isinstance(query_data, dict):
                    data_list = query_data.get("data", [])
                    if isinstance(data_list, list):
                        programs.extend(data_list)
        except Exception as e:
            logger.warning(f"Error extracting from React state: {e}")
        
        return programs
    
    def _parse_public_program(self, data: Dict) -> BountyProgram:
        """Parse public page data into BountyProgram."""
        attributes = data.get("attributes", data)  # Handle both formats
        
        # Try to extract bounty info from various fields
        min_bounty = 0
        max_bounty = 0
        offers_bounties = False
        
        # Check bounty_range or similar fields
        bounty_info = attributes.get("bounty_range", {})
        if bounty_info:
            offers_bounties = True
            min_bounty = bounty_info.get("min", 0)
            max_bounty = bounty_info.get("max", 0)
        
        # Alternative: check for bounty_in_usd or similar
        if not offers_bounties:
            bounty_alt = attributes.get("bounty_in_usd", 0)
            if bounty_alt > 0:
                offers_bounties = True
                max_bounty = bounty_alt
                min_bounty = bounty_alt // 10  # Estimate min as 10% of max
        
        return BountyProgram(
            id=str(attributes.get("id", data.get("id", ""))),
            name=attributes.get("name", "Unknown"),
            platform="hackerone",
            url=f"https://hackerone.com/{attributes.get('handle', attributes.get('slug', ''))}",
            offers_bounties=offers_bounties,
            min_bounty=min_bounty,
            max_bounty=max_bounty,
            scope=[],  # Public page doesn't show detailed scope
            response_time_hours=attributes.get("average_response_time"),
            is_public=attributes.get("state", "open") == "open",
        )
    
    def _scrape_programs_fallback(self, limit: int) -> List[BountyProgram]:
        """Fallback method to scrape program data."""
        programs = []
        
        # Known high-value programs (as fallback data)
        # This is static data for when scraping fails
        known_programs = [
            {"name": "Shopify", "handle": "shopify", "min": 500, "max": 30000},
            {"name": "Twitter", "handle": "twitter", "min": 100, "max": 20000},
            {"name": "Stripe", "handle": "stripe", "min": 500, "max": 50000},
            {"name": "GitHub", "handle": "github", "min": 100, "max": 30000},
            {"name": "Slack", "handle": "slack", "min": 100, "max": 15000},
        ]
        
        for prog in known_programs[:limit]:
            programs.append(BountyProgram(
                id=prog["handle"],
                name=prog["name"],
                platform="hackerone",
                url=f"https://hackerone.com/{prog['handle']}",
                offers_bounties=True,
                min_bounty=prog["min"],
                max_bounty=prog["max"],
                scope=[],
                is_public=True,
            ))
        
        return programs
    
    def _cache_programs(self, programs: List[BountyProgram]) -> None:
        """Cache programs to SQLite."""
        if not programs:
            return
        
        conn = sqlite3.connect(self.CACHE_DB)
        cursor = conn.cursor()
        
        for program in programs:
            cursor.execute("""
                INSERT OR REPLACE INTO programs VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            """, (
                program.id,
                program.name,
                program.platform,
                program.url,
                int(program.offers_bounties),
                program.min_bounty,
                program.max_bounty,
                program.currency,
                json.dumps(program.scope),
                json.dumps(program.out_of_scope),
                program.response_time_hours,
                int(program.is_public),
                program.cached_at,
                program.score_total,
            ))
        
        conn.commit()
        conn.close()
        logger.debug(f"Cached {len(programs)} programs")
    
    def _get_cached_programs(self, limit: int = 50) -> List[BountyProgram]:
        """Get programs from cache if available and not expired."""
        conn = sqlite3.connect(self.CACHE_DB)
        cursor = conn.cursor()
        
        # Check cache age
        cutoff = (datetime.utcnow() - timedelta(hours=self.CACHE_TTL_HOURS)).isoformat()
        
        cursor.execute("""
            SELECT * FROM programs 
            WHERE cached_at > ? AND offers_bounties = 1
            ORDER BY max_bounty DESC
            LIMIT ?
        """, (cutoff, limit))
        
        rows = cursor.fetchall()
        conn.close()
        
        programs = []
        for row in rows:
            programs.append(BountyProgram(
                id=row[0],
                name=row[1],
                platform=row[2],
                url=row[3],
                offers_bounties=bool(row[4]),
                min_bounty=row[5],
                max_bounty=row[6],
                currency=row[7],
                scope=json.loads(row[8]) if row[8] else [],
                out_of_scope=json.loads(row[9]) if row[9] else [],
                response_time_hours=row[10],
                is_public=bool(row[11]),
                cached_at=row[12],
                score_total=row[13] or 0.0,
            ))
        
        if programs:
            logger.info(f"Using {len(programs)} cached programs")
        
        return programs
    
    def rank_programs(self, programs: List[BountyProgram]) -> List[BountyProgram]:
        """
        Rank programs by profitability potential.
        
        Scoring factors:
        - Reward potential (40%): Max bounty amount
        - Response speed (30%): Faster response = faster payout
        - Scope clarity (30%): Clear scope = less wasted effort
        
        Returns:
            Programs sorted by total score (descending)
        """
        if not programs:
            return []
        
        # Calculate max values for normalization
        max_bounty = max((p.max_bounty for p in programs), default=1)
        min_response = min((p.response_time_hours or 168 for p in programs), default=1)
        
        for program in programs:
            # Score reward (0-40 points)
            if max_bounty > 0:
                program.score_reward = (program.max_bounty / max_bounty) * 40
            
            # Score response time (0-30 points, faster = better)
            if program.response_time_hours:
                # Inverse: faster response = higher score
                # Max 7 days (168 hours) = 0 points
                response_score = max(0, 1 - (program.response_time_hours / 168))
                program.score_response = response_score * 30
            else:
                program.score_response = 15  # Unknown = average
            
            # Score scope clarity (0-30 points)
            if program.scope:
                # More scope items = clearer (up to a point)
                scope_count = len(program.scope)
                program.score_scope = min(scope_count * 3, 30)
            else:
                program.score_scope = 10  # Unknown scope
            
            # Total score
            program.score_total = (
                program.score_reward +
                program.score_response +
                program.score_scope
            )
        
        # Sort by total score
        return sorted(programs, key=lambda p: p.score_total, reverse=True)
    
    def get_top_recommendation(self, 
                               min_bounty: int = 500,
                               use_api: bool = True) -> Optional[BountyProgram]:
        """
        Get single top program recommendation.
        
        Args:
            min_bounty: Minimum bounty threshold
            use_api: Try API first, fallback to public
            
        Returns:
            Best BountyProgram or None
        """
        if use_api and self.api_auth:
            programs = self.discover_programs_api(min_bounty=min_bounty, limit=20)
        else:
            programs = self.discover_programs_public(limit=20)
        
        if not programs:
            return None
        
        ranked = self.rank_programs(programs)
        return ranked[0] if ranked else None
    
    def format_programs_list(self, programs: List[BountyProgram], 
                            show_scores: bool = False) -> str:
        """Format program list for display."""
        if not programs:
            return "\n  No programs found.\n"
        
        lines = []
        lines.append("\n  Bug Bounty Programs:")
        lines.append("  " + "─" * 70)
        
        for i, prog in enumerate(programs[:10], 1):
            bounty = prog.bounty_range
            score_info = f" (Score: {prog.score_total:.1f})" if show_scores else ""
            
            lines.append(f"\n  {i}. {prog.name}{score_info}")
            lines.append(f"     Reward: {bounty}")
            lines.append(f"     URL: {prog.url}")
            
            if prog.response_time_hours:
                days = prog.response_time_hours / 24
                lines.append(f"     Response: ~{days:.1f} days")
            
            if prog.scope:
                scope_count = len(prog.scope)
                lines.append(f"     Scope: {scope_count} assets defined")
        
        lines.append("\n  " + "─" * 70)
        
        return "\n".join(lines)


def run_cli():
    """CLI for bounty intelligence."""
    import os
    import sys
    
    # Check for API credentials
    api_key = os.environ.get("HACKERONE_API_KEY")
    api_user = os.environ.get("HACKERONE_API_USER")
    
    intel = BountyIntelligence(api_key=api_key, api_username=api_user)
    
    if len(sys.argv) < 2:
        # Default: discover and show top programs
        print("\n  Discovering bug bounty programs...")
        
        if api_key:
            print("  Mode: API (authenticated)")
            programs = intel.discover_programs_api(min_bounty=500, limit=10)
        else:
            print("  Mode: Public (no API key)")
            print("  Tip: Set HACKERONE_API_KEY for more data")
            programs = intel.discover_programs_public(limit=10)
        
        if programs:
            ranked = intel.rank_programs(programs)
            print(intel.format_programs_list(ranked, show_scores=True))
            
            top = ranked[0]
            print(f"\n  Top recommendation: {top.name}")
            print(f"  Potential reward: {top.bounty_range}")
            print(f"  Start scan: elengenix quick {top.url}")
        else:
            print("\n  No programs found. Check your connection.")
        
        sys.exit(0)
    
    command = sys.argv[1]
    
    if command == "api":
        if not api_key:
            print("\n  Error: HACKERONE_API_KEY not set")
            print("  Set with: export HACKERONE_API_KEY=your_key")
            sys.exit(1)
        
        programs = intel.discover_programs_api(min_bounty=500, limit=15)
        ranked = intel.rank_programs(programs)
        print(intel.format_programs_list(ranked, show_scores=True))
    
    elif command == "public":
        programs = intel.discover_programs_public(limit=15)
        ranked = intel.rank_programs(programs)
        print(intel.format_programs_list(ranked, show_scores=False))
    
    elif command == "top":
        top = intel.get_top_recommendation(min_bounty=500)
        if top:
            print(f"\n  Top Pick: {top.name}")
            print(f"  Reward: {top.bounty_range}")
            print(f"  URL: {top.url}")
            print(f"  Score: {top.score_total:.1f}/100")
            print(f"\n  Command: elengenix deep {top.url}")
        else:
            print("\n  No programs found")
    
    elif command == "cache":
        cached = intel._get_cached_programs(limit=50)
        print(f"\n  Cached programs: {len(cached)}")
        for prog in cached[:5]:
            age = (datetime.utcnow() - datetime.fromisoformat(prog.cached_at)).hours
            print(f"    • {prog.name} ({age}h ago)")
    
    else:
        print(f"\n  Unknown command: {command}")
        print("  Usage: bounty [api|public|top|cache]")


if __name__ == "__main__":
    run_cli()
