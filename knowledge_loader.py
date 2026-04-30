"""
knowledge_loader.py — Elengenix Knowledge Hub (v1.5.0)
- Path Traversal Protection via Pathlib.resolve()
- Token Usage Control (Strict Character Limits)
- Robust Error Handling and Encoding Support
- Prompt Injection Prevention in Knowledge Files
"""

import logging
import re
from pathlib import Path
from typing import Optional, Set
from functools import lru_cache

# Configuration Constants
MAX_TOTAL_CHARS = 8000
MAX_PER_FILE_CHARS = 2000
MAX_FILE_SIZE_BYTES = 1024 * 1024 # 1MB
ALLOWED_EXTENSIONS = {".txt", ".md"}
SAFE_ENCODING = "utf-8"

# Logging Setup
logger = logging.getLogger("elengenix.knowledge")

def sanitize_content(text: str) -> str:
    """ Prevents Prompt Injection within knowledge base files."""
    dangerous_patterns = [
        r"ignore previous instructions",
        r"you are now in developer mode",
        r"system override",
        r"### USER:",
        r"### ASSISTANT:"
    ]
    for pattern in dangerous_patterns:
        text = re.sub(pattern, "[REDACTED_BY_SECURITY]", text, flags=re.IGNORECASE)
    return text

def load_knowledge_base(
    knowledge_dir: str = "knowledge",
    max_chars: int = MAX_TOTAL_CHARS
) -> str:
    """
    Securely loads knowledge files with strict resource limits.
    """
    try:
        #  Path Traversal Protection
        base_path = Path(knowledge_dir).resolve()
        project_root = Path(__file__).parent.resolve()
        
        if not str(base_path).startswith(str(project_root)):
            logger.warning(f"Unauthorized path blocked: {knowledge_dir}")
            return ""
            
    except Exception as e:
        logger.error(f"Invalid path resolution: {e}")
        return ""

    if not base_path.exists() or not base_path.is_dir():
        return ""

    parts = []
    current_total = 0
    
    for file_path in base_path.glob("*"):
        if not file_path.is_file() or file_path.suffix.lower() not in ALLOWED_EXTENSIONS:
            continue

        #  File Size Guard
        try:
            if file_path.stat().st_size > MAX_FILE_SIZE_BYTES:
                logger.warning(f"Skipping oversized file: {file_path.name}")
                continue
            
            # Read content with explicit encoding
            raw_text = file_path.read_text(encoding=SAFE_ENCODING, errors="replace")
            clean_text = sanitize_content(raw_text)
            
            # Truncate individual file if necessary
            if len(clean_text) > MAX_PER_FILE_CHARS:
                clean_text = clean_text[:MAX_PER_FILE_CHARS] + "\n[File Truncated]"
                
            header = f"--- Source: {file_path.name} ---\n"
            entry = header + clean_text
            
            # Global Token Budget Check
            if current_total + len(entry) > max_chars:
                remaining = max_chars - current_total
                if remaining > 50:
                    parts.append(entry[:remaining] + "\n[Global Context Limit Reached]")
                break
            
            parts.append(entry)
            current_total += len(entry)
            
        except Exception as e:
            logger.error(f"Error processing {file_path.name}: {e}")
            continue

    if not parts:
        return ""

    return "\n\n### SUPPLEMENTARY KNOWLEDGE BASE:\n" + "\n\n".join(parts)

@lru_cache(maxsize=1)
def load_knowledge_cached() -> str:
    """Efficiency: Caches the knowledge base to prevent frequent Disk I/O."""
    return load_knowledge_base()
