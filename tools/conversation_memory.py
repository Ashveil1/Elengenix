"""tools/conversation_memory.py

Conversation Memory for AI Assistant.

Purpose:
    pass  # TODO: Implement
- Remember conversation history across sessions
- Context-aware responses
- SQLite-backed persistence
- Export/import conversations
"""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

logger = logging.getLogger("elengenix.conversation_memory")


@dataclass
class ConversationMessage:
    """Single message in conversation."""
    role: str  # user / assistant / system
    content: str
    timestamp: str
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class ConversationSession:
    """Full conversation session."""
    session_id: str
    started_at: str
    updated_at: str
    target: Optional[str] = None
    mode: str = "bug_bounty"  # bug_bounty / universal
    messages: List[ConversationMessage] = None
    
    def __post_init__(self):
        if self.messages is None:
            self.messages = []


class ConversationMemory:
    """
    SQLite-backed conversation memory.
    """
    
    def __init__(self, db_path: Path = Path("data/conversations.db")):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
    
    def _init_db(self) -> None:
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS conversations (
                    session_id TEXT PRIMARY KEY,
                    started_at TEXT,
                    updated_at TEXT,
                    target TEXT,
                    mode TEXT,
                    messages TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS conversation_summary (
                    session_id TEXT PRIMARY KEY,
                    summary TEXT,
                    key_findings TEXT,
                    tools_used TEXT,
                    FOREIGN KEY (session_id) REFERENCES conversations(session_id)
                )
            """)
    
    def create_session(self, target: Optional[str] = None, mode: str = "bug_bounty") -> str:
        """Create new conversation session."""
        session_id = str(uuid4())[:12]
        now = datetime.now().isoformat()
        
        session = ConversationSession(
            session_id=session_id,
            started_at=now,
            updated_at=now,
            target=target,
            mode=mode,
            messages=[]
        )
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO conversations VALUES (?, ?, ?, ?, ?, ?)",
                (session_id, now, now, target, mode, "[]")
            )
        
        return session_id
    
    def add_message(
        self, 
        session_id: str, 
        role: str, 
        content: str, 
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Add message to session."""
        message = ConversationMessage(
            role=role,
            content=content,
            timestamp=datetime.now().isoformat(),
            metadata=metadata
        )
        
        # Load existing messages
        session = self.get_session(session_id)
        if not session:
            logger.warning(f"Session {session_id} not found")
            return
        
        session.messages.append(message)
        session.updated_at = datetime.now().isoformat()
        
        # Save back
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE conversations SET messages = ?, updated_at = ? WHERE session_id = ?",
                (json.dumps([asdict(m) for m in session.messages]), session.updated_at, session_id)
            )
    
    def get_session(self, session_id: str) -> Optional[ConversationSession]:
        """Get full session by ID."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM conversations WHERE session_id = ?",
                (session_id,)
            ).fetchone()
            
            if not row:
                return None
            
            messages_raw = json.loads(row[5]) if row[5] else []
            messages = [ConversationMessage(**m) for m in messages_raw]
            
            return ConversationSession(
                session_id=row[0],
                started_at=row[1],
                updated_at=row[2],
                target=row[3],
                mode=row[4],
                messages=messages
            )
    
    def get_recent_context(self, session_id: str, limit: int = 10) -> List[Dict[str, str]]:
        """Get recent messages for context."""
        session = self.get_session(session_id)
        if not session:
            return []
        
        recent = session.messages[-limit:] if len(session.messages) > limit else session.messages
        
        return [
            {"role": m.role, "content": m.content}
            for m in recent
        ]
    
    def get_conversation_summary(self, session_id: str) -> str:
        """Generate summary of conversation."""
        session = self.get_session(session_id)
        if not session:
            return "No conversation history."
        
        # Count messages
        user_msgs = sum(1 for m in session.messages if m.role == "user")
        ai_msgs = sum(1 for m in session.messages if m.role == "assistant")
        
        # Extract tools mentioned
        tools_mentioned = set()
        for m in session.messages:
            for tool in ["bola", "waf", "recon", "scan", "predict", "report"]:
                if tool in m.content.lower():
                    tools_mentioned.add(tool)
        
        summary = f"""
📊 Session Summary: {session_id}
🎯 Target: {session.target or 'Not specified'}
💬 Messages: {user_msgs} user, {ai_msgs} assistant
🛠️ Tools discussed: {', '.join(tools_mentioned) if tools_mentioned else 'None'}
⏱️ Duration: {session.started_at[:19]} → {session.updated_at[:19]}
"""
        return summary
    
    def list_sessions(self, limit: int = 10) -> List[Dict[str, Any]]:
        """List recent sessions."""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                """SELECT session_id, target, mode, updated_at 
                   FROM conversations 
                   ORDER BY updated_at DESC 
                   LIMIT ?""",
                (limit,)
            ).fetchall()
        
        return [
            {
                "session_id": r[0],
                "target": r[1],
                "mode": r[2],
                "last_active": r[3][:19]
            }
            for r in rows
        ]
    
    def delete_session(self, session_id: str) -> bool:
        """Delete session."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM conversation_summary WHERE session_id = ?", (session_id,))
            result = conn.execute(
                "DELETE FROM conversations WHERE session_id = ?",
                (session_id,)
            )
            return result.rowcount > 0
    
    def export_session(self, session_id: str, format: str = "json") -> str:
        """Export session to file."""
        session = self.get_session(session_id)
        if not session:
            return ""
        
        if format == "json":
            data = {
                "session_id": session.session_id,
                "target": session.target,
                "mode": session.mode,
                "started_at": session.started_at,
                "messages": [
                    {
                        "role": m.role,
                        "content": m.content,
                        "time": m.timestamp
                    }
                    for m in session.messages
                ]
            }
            
            export_path = Path(f"exports/conversation_{session_id}.json")
            export_path.parent.mkdir(exist_ok=True)
            export_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            return str(export_path)
        
        elif format == "markdown":
            lines = [
                f"# Conversation: {session.session_id}",
                f"**Target:** {session.target or 'N/A'}",
                f"**Mode:** {session.mode}",
                f"**Started:** {session.started_at[:19]}",
                "\n---\n"
            ]
            
            for m in session.messages:
                role = "🧑 User" if m.role == "user" else "🤖 Assistant"
                lines.append(f"\n### {role} ({m.timestamp[:19]})\n")
                lines.append(m.content)
                lines.append("\n")
            
            export_path = Path(f"exports/conversation_{session_id}.md")
            export_path.parent.mkdir(exist_ok=True)
            export_path.write_text("\n".join(lines), encoding="utf-8")
            return str(export_path)
        
        return ""


class ProfessionalAIPrompts:
    """
    Professional, polite AI prompts for bug bounty hunters.
    """
    
    SYSTEM_PROMPT = """You are Elengenix AI, a professional security assessment assistant for authorized bug bounty hunting and penetration testing.

Personality:
    pass  # TODO: Implement
- Professional, courteous, and respectful
- Focused on security research and vulnerability discovery
- Always emphasize responsible disclosure
- Never use aggressive or criminal terminology

Available Commands (you can guide users to use these):
    pass  # TODO: Implement
CORE COMMANDS:
    pass  # TODO: Implement
- ai: Interactive chat with me (this mode)
- autonomous <target> [--mode auto]: Full AI-controlled security scan
- scan <target>: Quick vulnerability scan
- quick <target>: Fast 2-minute reconnaissance
- deep <target>: Comprehensive scan with all tools

SCANNING COMMANDS:
    pass  # TODO: Implement
- recon <target>: Discover assets, subdomains, endpoints
- bola <target>: Test BOLA/IDOR access control vulnerabilities
- waf <target>: WAF detection and bypass testing

RESEARCH COMMANDS:
    pass  # TODO: Implement
- research <CVE-id|vuln-type>: Research CVEs and vulnerabilities
- poc <vuln-type> [--framework <name>]: Generate proof-of-concept code

UTILITY COMMANDS:
    pass  # TODO: Implement
- bounty <target>: Focus on high-value bounty vulnerabilities
- stealth <target>: Slow scan with evasion techniques
- api <target>: API-focused security testing
- web <target>: Web application testing
- evasion: EDR/AV evasion techniques (red team)
- report: Generate professional PDF/HTML reports

SYSTEM COMMANDS:
    pass  # TODO: Implement
- welcome: First-time setup wizard
- configure: Configure AI providers and settings
- doctor: Check system health
- history: View command history and suggestions
- profile: Manage command profiles
- help: Show all available commands

Guidelines:
    pass  # TODO: Implement
- Refer to activities as "security testing", "assessment", or "research" (not "hacking")
- Emphasize authorization and legal scope
- Provide clear, actionable technical guidance
- Prioritize safety and data protection
- When user wants to do something, suggest the appropriate command
- If user doesn't know what to type, guide them step by step

When starting:
    pass  # TODO: Implement
- Ask what target the user would like to assess
- Confirm scope and authorization before proceeding
- Offer to guide through the security testing process
- If user says "I want to scan" or "find bugs", ask for target then suggest appropriate command

Language: Respond in the same language as the user's query (Thai or English)."""
    
    WELCOME_MESSAGES = {
        "th": """
+==============================================================+
|         ELENGENIX AI - Professional Security Assistant       |
+==============================================================+

Hello! Ready to provide security testing assistance.

Services offered:
    pass  # TODO: Implement
  • Security vulnerability assessment
  • Access control testing (BOLA/IDOR)
  • Security control effectiveness review
  • Professional report generation

Type /help for commands or specify your target.

Please specify the target you would like to assess:
    pass  # TODO: Implement
""",
        "en": """
+==============================================================+
|         ELENGENIX AI - Professional Security Assistant       |
+==============================================================+

Welcome! Ready to assist with authorized security testing.

Services offered:
    pass  # TODO: Implement
  • Security vulnerability assessment
  • Access control testing (BOLA/IDOR)
  • Security control effectiveness review
  • Professional report generation

Type /help for commands or specify your target.

Please specify the target you would like to assess:
    pass  # TODO: Implement
"""
    }
    
    @staticmethod
    def get_welcome(language: str = "th") -> str:
        """Get professional welcome message."""
        return ProfessionalAIPrompts.WELCOME_MESSAGES.get(language, ProfessionalAIPrompts.WELCOME_MESSAGES["en"])
    
    @staticmethod
    def build_context_aware_prompt(
        user_input: str,
        conversation_history: List[Dict[str, str]],
        target: Optional[str] = None,
        language: str = "th"
    ) -> str:
        """Build prompt with conversation context."""
        
        # Build context from history
        context_parts = []
        if target:
            context_parts.append(f"Current assessment target: {target}")
        
        if conversation_history:
            context_parts.append("Previous conversation context:")
            for msg in conversation_history[-5:]:  # Last 5 messages
                role = "User" if msg["role"] == "user" else "Assistant"
                # Truncate long messages
                content = msg["content"][:100] + "..." if len(msg["content"]) > 100 else msg["content"]
                context_parts.append(f"{role}: {content}")
        
        context = "\n".join(context_parts) if context_parts else ""
        
        # Build full prompt
        prompt_parts = [
            ProfessionalAIPrompts.SYSTEM_PROMPT,
            "",
            context,
            "",
            f"User query ({language}): {user_input}",
            "",
            "Respond professionally and helpfully:"
        ]
        
        return "\n".join(prompt_parts)
