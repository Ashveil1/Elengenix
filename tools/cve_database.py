"""
tools/cve_database.py — CVE Database & Vulnerability Intelligence (v1.0.0)
- Local CVE cache for offline analysis
- NVD (National Vulnerability Database) integration
- AI-powered vulnerability matching
- Historical and latest CVE tracking
"""

import json
import logging
import re
import sqlite3
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any
import requests
from urllib.parse import urlencode

logger = logging.getLogger("elengenix.cve")

# CVE Database paths
DATA_DIR = Path("data")
CVE_DB_PATH = DATA_DIR / "cve_database.db"
CVE_CACHE_DIR = DATA_DIR / "cve_cache"
CVE_CACHE_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class CVEEntry:
    """Represents a single CVE entry."""
    cve_id: str
    description: str
    published_date: str
    last_modified: str
    cvss_score: float = 0.0
    cvss_vector: str = ""
    severity: str = "Unknown"
    cwe_ids: List[str] = None
    ref_urls: List[str] = None
    affected_products: List[str] = None
    exploit_available: bool = False
    
    def __post_init__(self):
        if self.cwe_ids is None:
            self.cwe_ids = []
        if self.ref_urls is None:
            self.ref_urls = []
        if self.affected_products is None:
            self.affected_products = []


class CVEDatabase:
    """
    Local CVE database with NVD integration.
    Provides offline CVE lookup and AI analysis capabilities.
    """
    
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, auto_update: bool = True):
        self.auto_update = auto_update
        self._init_database()
        
        # Check if database needs update (older than 7 days)
        if auto_update and self._needs_update():
            logger.info("CVE database needs update. Run update_database() to fetch latest CVEs.")
    
    def _init_database(self):
        """Initialize SQLite database for CVE storage."""
        DATA_DIR.mkdir(exist_ok=True)
        
        conn = sqlite3.connect(str(CVE_DB_PATH))
        cursor = conn.cursor()
        
        # Main CVE table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                published_date TEXT,
                last_modified TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                severity TEXT,
                cwe_ids TEXT,  -- JSON array
                ref_urls TEXT,  -- JSON array (renamed from references)
                affected_products TEXT,  -- JSON array
                exploit_available INTEGER,
                keywords TEXT,  -- For search indexing
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create indexes for faster search
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cvss ON cves(cvss_score)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_severity ON cves(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_published ON cves(published_date)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_keywords ON cves(keywords)")
        
        # Metadata table for tracking updates
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        conn.close()
        logger.info("CVE database initialized.")
    
    def _needs_update(self) -> bool:
        """Check if database needs update (older than 7 days)."""
        conn = sqlite3.connect(str(CVE_DB_PATH))
        cursor = conn.cursor()
        
        cursor.execute("SELECT value FROM metadata WHERE key = 'last_update'")
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return True
        
        last_update = datetime.fromisoformat(result[0])
        return datetime.now() - last_update > timedelta(days=7)
    
    def update_database(self, days_back: int = 30) -> Dict[str, Any]:
        """
        Fetch latest CVEs from NVD API and update local database.
        
        Args:
            days_back: Number of days to look back for new CVEs
            
        Returns:
            Dict with update statistics
        """
        logger.info(f"Fetching CVEs from NVD (last {days_back} days)...")
        
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days_back)
        
        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": 2000  # Max allowed by NVD
        }
        
        added_count = 0
        updated_count = 0
        
        try:
            # Fetch from NVD API with pagination
            start_index = 0
            total_results = 1
            
            while start_index < total_results:
                params["startIndex"] = start_index
                url = f"{self.NVD_API_BASE}?{urlencode(params)}"
                
                response = requests.get(url, timeout=30)
                response.raise_for_status()
                data = response.json()
                
                total_results = data.get("totalResults", 0)
                vulnerabilities = data.get("vulnerabilities", [])
                
                if not vulnerabilities:
                    break
                
                # Process each CVE
                for vuln in vulnerabilities:
                    cve_data = vuln.get("cve", {})
                    cve_id = cve_data.get("id", "")
                    
                    if not cve_id:
                        continue
                    
                    # Extract CVE details
                    cve_entry = self._parse_nvd_cve(cve_data)
                    
                    # Add to database
                    if self._cve_exists(cve_id):
                        self._update_cve(cve_entry)
                        updated_count += 1
                    else:
                        self._add_cve(cve_entry)
                        added_count += 1
                
                start_index += len(vulnerabilities)
                logger.info(f"Processed {start_index}/{total_results} CVEs...")
            
            # Update metadata
            self._set_metadata("last_update", datetime.now().isoformat())
            self._set_metadata("total_cves", str(self._count_cves()))
            
            logger.info(f"CVE update complete: {added_count} added, {updated_count} updated")
            return {
                "status": "success",
                "added": added_count,
                "updated": updated_count,
                "total": self._count_cves()
            }
            
        except Exception as e:
            logger.error(f"Failed to update CVE database: {e}")
            return {"status": "error", "error": str(e)}
    
    def _parse_nvd_cve(self, cve_data: Dict) -> CVEEntry:
        """Parse NVD API response into CVEEntry."""
        cve_id = cve_data.get("id", "")
        
        # Get description
        descriptions = cve_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        
        # Get dates
        published = cve_data.get("published", "")
        last_modified = cve_data.get("lastModified", "")
        
        # Get CVSS data
        metrics = cve_data.get("metrics", {})
        cvss_score = 0.0
        cvss_vector = ""
        severity = "Unknown"
        
        # Try CVSS 3.1 first, then 3.0, then 2.0
        for cvss_version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if cvss_version in metrics and metrics[cvss_version]:
                cvss_data = metrics[cvss_version][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "")
                severity = cvss_data.get("baseSeverity", "Unknown")
                break
        
        # Get CWEs
        weaknesses = cve_data.get("weaknesses", [])
        cwe_ids = []
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    cwe_id = desc.get("value", "")
                    if cwe_id.startswith("CWE-"):
                        cwe_ids.append(cwe_id)
        
        # Get references
        refs = cve_data.get("references", [])
        ref_urls = [ref.get("url", "") for ref in refs if ref.get("url")]
        
        # Check for exploit references
        exploit_available = any(
            any(keyword in ref.get("url", "").lower() for keyword in 
                ["exploit", "poc", "github.com", "gitlab.com"])
            for ref in refs
        )
        
        # Get affected products (from configurations)
        affected_products = []
        configurations = cve_data.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    criteria = cpe.get("criteria", "")
                    if criteria.startswith("cpe:"):
                        # Extract product name from CPE
                        parts = criteria.split(":")
                        if len(parts) >= 5:
                            product = f"{parts[3]}:{parts[4]}"
                            if product not in affected_products:
                                affected_products.append(product)
        
        # Create keywords for search
        keywords = f"{cve_id} {description} {' '.join(cwe_ids)}"
        keywords = keywords.lower()
        
        return CVEEntry(
            cve_id=cve_id,
            description=description,
            published_date=published,
            last_modified=last_modified,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            severity=severity,
            cwe_ids=cwe_ids,
            ref_urls=ref_urls,
            affected_products=affected_products,
            exploit_available=exploit_available
        )
    
    def _cve_exists(self, cve_id: str) -> bool:
        """Check if CVE already exists in database."""
        conn = sqlite3.connect(str(CVE_DB_PATH))
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM cves WHERE cve_id = ?", (cve_id,))
        result = cursor.fetchone()
        conn.close()
        return result is not None
    
    def _add_cve(self, entry: CVEEntry):
        """Add new CVE to database."""
        conn = sqlite3.connect(str(CVE_DB_PATH))
        cursor = conn.cursor()
        
        keywords = f"{entry.cve_id} {entry.description} {' '.join(entry.cwe_ids)}".lower()
        
        cursor.execute("""
            INSERT INTO cves (
                cve_id, description, published_date, last_modified,
                cvss_score, cvss_vector, severity, cwe_ids, ref_urls,
                affected_products, exploit_available, keywords
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            entry.cve_id, entry.description, entry.published_date,
            entry.last_modified, entry.cvss_score, entry.cvss_vector,
            entry.severity, json.dumps(entry.cwe_ids),
            json.dumps(entry.ref_urls), json.dumps(entry.affected_products),
            1 if entry.exploit_available else 0, keywords
        ))
        
        conn.commit()
        conn.close()
    
    def _update_cve(self, entry: CVEEntry):
        """Update existing CVE in database."""
        conn = sqlite3.connect(str(CVE_DB_PATH))
        cursor = conn.cursor()
        
        keywords = f"{entry.cve_id} {entry.description} {' '.join(entry.cwe_ids)}".lower()
        
        cursor.execute("""
            UPDATE cves SET
                description = ?, last_modified = ?, cvss_score = ?,
                cvss_vector = ?, severity = ?, cwe_ids = ?, ref_urls = ?,
                affected_products = ?, exploit_available = ?, keywords = ?
            WHERE cve_id = ?
        """, (
            entry.description, entry.last_modified, entry.cvss_score,
            entry.cvss_vector, entry.severity, json.dumps(entry.cwe_ids),
            json.dumps(entry.ref_urls), json.dumps(entry.affected_products),
            1 if entry.exploit_available else 0, keywords, entry.cve_id
        ))
        
        conn.commit()
        conn.close()
    
    def _count_cves(self) -> int:
        """Count total CVEs in database."""
        conn = sqlite3.connect(str(CVE_DB_PATH))
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM cves")
        count = cursor.fetchone()[0]
        conn.close()
        return count
    
    def _set_metadata(self, key: str, value: str):
        """Set metadata value."""
        conn = sqlite3.connect(str(CVE_DB_PATH))
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO metadata (key, value, updated_at)
            VALUES (?, ?, ?)
        """, (key, value, datetime.now().isoformat()))
        conn.commit()
        conn.close()
    
    def search_cves(
        self,
        query: str = "",
        severity: str = "",
        min_cvss: float = 0.0,
        max_cvss: float = 10.0,
        cwe_id: str = "",
        has_exploit: Optional[bool] = None,
        limit: int = 50
    ) -> List[CVEEntry]:
        """
        Search CVEs with multiple filters.
        
        Args:
            query: Text search in description and CVE ID
            severity: Filter by severity (Critical, High, Medium, Low)
            min_cvss: Minimum CVSS score
            max_cvss: Maximum CVSS score
            cwe_id: Filter by CWE category
            has_exploit: Filter by exploit availability
            limit: Maximum results
        """
        conn = sqlite3.connect(str(CVE_DB_PATH))
        cursor = conn.cursor()
        
        conditions = ["cvss_score >= ?", "cvss_score <= ?"]
        params = [min_cvss, max_cvss]
        
        if query:
            conditions.append("(cve_id LIKE ? OR keywords LIKE ?)")
            params.extend([f"%{query}%", f"%{query.lower()}%"])
        
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        
        if cwe_id:
            conditions.append("cwe_ids LIKE ?")
            params.append(f"%{cwe_id}%")
        
        if has_exploit is not None:
            conditions.append("exploit_available = ?")
            params.append(1 if has_exploit else 0)
        
        where_clause = " AND ".join(conditions)
        
        cursor.execute(f"""
            SELECT * FROM cves
            WHERE {where_clause}
            ORDER BY cvss_score DESC, published_date DESC
            LIMIT ?
        """, params + [limit])
        
        rows = cursor.fetchall()
        conn.close()
        
        return [self._row_to_entry(row) for row in rows]
    
    def get_cve(self, cve_id: str) -> Optional[CVEEntry]:
        """Get specific CVE by ID."""
        conn = sqlite3.connect(str(CVE_DB_PATH))
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return self._row_to_entry(row)
        return None
    
    def _row_to_entry(self, row) -> CVEEntry:
        """Convert database row to CVEEntry."""
        return CVEEntry(
            cve_id=row[0],
            description=row[1],
            published_date=row[2],
            last_modified=row[3],
            cvss_score=row[4],
            cvss_vector=row[5],
            severity=row[6],
            cwe_ids=json.loads(row[7]) if row[7] else [],
            ref_urls=json.loads(row[8]) if row[8] else [],
            affected_products=json.loads(row[9]) if row[9] else [],
            exploit_available=bool(row[10])
        )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        conn = sqlite3.connect(str(CVE_DB_PATH))
        cursor = conn.cursor()
        
        stats = {
            "total_cves": self._count_cves(),
            "by_severity": {},
            "by_year": {},
            "exploitable": 0
        }
        
        # Count by severity
        cursor.execute("SELECT severity, COUNT(*) FROM cves GROUP BY severity")
        for row in cursor.fetchall():
            stats["by_severity"][row[0]] = row[1]
        
        # Count by year
        cursor.execute("""
            SELECT substr(published_date, 1, 4) as year, COUNT(*)
            FROM cves GROUP BY year ORDER BY year
        """)
        for row in cursor.fetchall():
            if row[0] and row[0].isdigit():
                stats["by_year"][row[0]] = row[1]
        
        # Count exploitable
        cursor.execute("SELECT COUNT(*) FROM cves WHERE exploit_available = 1")
        stats["exploitable"] = cursor.fetchone()[0]
        
        # Last update
        cursor.execute("SELECT value FROM metadata WHERE key = 'last_update'")
        result = cursor.fetchone()
        stats["last_update"] = result[0] if result else "Never"
        
        conn.close()
        return stats
    
    def find_similar_vulns(
        self,
        finding_type: str,
        product: str = "",
        cvss_range: Tuple[float, float] = (7.0, 10.0)
    ) -> List[CVEEntry]:
        """
        Find CVEs similar to a vulnerability type.
        Used by AI for vulnerability comparison.
        """
        # Map common vulnerability types to keywords
        vuln_keywords = {
            "xss": ["cross-site scripting", "xss", "html injection"],
            "sqli": ["sql injection", "sqli", "sql command"],
            "rce": ["remote code execution", "rce", "command injection"],
            "lfi": ["local file inclusion", "lfi", "directory traversal"],
            "rfi": ["remote file inclusion", "rfi"],
            "ssrf": ["server-side request forgery", "ssrf"],
            "xxe": ["xml external entity", "xxe"],
            "idor": ["insecure direct object reference", "idor"],
            "path_traversal": ["path traversal", "directory traversal"],
            "csrf": ["cross-site request forgery", "csrf"],
            "open_redirect": ["open redirect", "url redirection"],
            "information_disclosure": ["information disclosure", "information leak"],
        }
        
        keywords = vuln_keywords.get(finding_type.lower(), [finding_type])
        
        results = []
        for keyword in keywords:
            cves = self.search_cves(
                query=keyword,
                min_cvss=cvss_range[0],
                max_cvss=cvss_range[1],
                limit=10
            )
            results.extend(cves)
        
        # Remove duplicates and sort by CVSS
        seen = set()
        unique_results = []
        for cve in results:
            if cve.cve_id not in seen:
                seen.add(cve.cve_id)
                unique_results.append(cve)
        
        return sorted(unique_results, key=lambda x: x.cvss_score, reverse=True)[:20]


# Global instance for easy access
_cve_db = None

def get_cve_database(auto_update: bool = True) -> CVEDatabase:
    """Get or create CVEDatabase singleton."""
    global _cve_db
    if _cve_db is None:
        _cve_db = CVEDatabase(auto_update=auto_update)
    return _cve_db


def format_cve_for_ai(cve: CVEEntry) -> str:
    """Format CVE entry for AI analysis."""
    lines = [
        f"CVE ID: {cve.cve_id}",
        f"CVSS Score: {cve.cvss_score} ({cve.severity})",
        f"Published: {cve.published_date[:10] if cve.published_date else 'Unknown'}",
        f"Description: {cve.description[:200]}..." if len(cve.description) > 200 else f"Description: {cve.description}",
    ]
    
    if cve.cwe_ids:
        lines.append(f"CWE Categories: {', '.join(cve.cwe_ids)}")
    
    if cve.exploit_available:
        lines.append(" Public exploit available")
    
    if cve.affected_products:
        lines.append(f"Affected: {', '.join(cve.affected_products[:3])}")
    
    return "\n".join(lines)


if __name__ == "__main__":
    # Test the CVE database
    logging.basicConfig(level=logging.INFO)
    
    db = get_cve_database(auto_update=False)
    
    print("CVE Database Test")
    print("=" * 50)
    
    # Show stats
    stats = db.get_stats()
    print(f"Total CVEs: {stats['total_cves']}")
    print(f"Last update: {stats['last_update']}")
    
    if stats['total_cves'] == 0:
        print("\nDatabase is empty. Run update_database() to fetch CVEs.")
    else:
        # Search for high-severity XSS
        print("\nSearching for XSS vulnerabilities...")
        results = db.search_cves(query="XSS", min_cvss=7.0, limit=5)
        for cve in results:
            print(f"\n{cve.cve_id}: {cve.cvss_score} ({cve.severity})")
            print(f"  {cve.description[:100]}...")
    
    print("\n" + "=" * 50)
    print("To populate database, run: python -c 'from tools.cve_database import get_cve_database; get_cve_database().update_database()'")
