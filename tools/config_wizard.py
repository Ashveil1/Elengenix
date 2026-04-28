"""tools/config_wizard.py

Configuration Wizard - Interactive setup for Elengenix.

Purpose:
- Configure AI providers and API keys
- Set default preferences
- Initialize project settings
- Check configuration status
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from ui_components import console, print_info, print_success, print_warning, print_error


@dataclass
class AIProviderConfig:
    """AI Provider configuration."""
    name: str
    env_key: str
    base_url: str
    signup_url: str
    is_free: bool
    notes: str


class ConfigWizard:
    """Interactive configuration wizard."""
    
    AI_PROVIDERS = [
        AIProviderConfig(
            name="Gemini (Google)",
            env_key="GEMINI_API_KEY",
            base_url="https://generativelanguage.googleapis.com/v1beta/openai",
            signup_url="https://aistudio.google.com/app/apikey",
            is_free=True,
            notes="ฟรี, เร็ว, ดีภาษาไทย (recommended)",
        ),
        AIProviderConfig(
            name="OpenAI (GPT-4)",
            env_key="OPENAI_API_KEY",
            base_url="https://api.openai.com/v1",
            signup_url="https://platform.openai.com/api-keys",
            is_free=False,
            notes="แม่นยำแต่เสียตัง, ต้องมี credit card",
        ),
        AIProviderConfig(
            name="Groq",
            env_key="GROQ_API_KEY",
            base_url="https://api.groq.com/openai/v1",
            signup_url="https://console.groq.com/keys",
            is_free=True,
            notes="เร็วมาก, Llama 3.1 ฟรี",
        ),
        AIProviderConfig(
            name="Ollama (Local)",
            env_key="",
            base_url="http://localhost:11434/v1",
            signup_url="https://ollama.com/download",
            is_free=True,
            notes="ไม่ต้อง API key, รันบนเครื่องตัวเอง",
        ),
    ]
    
    def __init__(self, config_dir: Path = Path(".")):
        self.config_dir = config_dir
        self.env_file = config_dir / ".env"
    
    def run(self) -> None:
        """Run the configuration wizard."""
        console.print("""
╔════════════════════════════════════════════════════════════════╗
║           ⚙️ ELENGENIX CONFIGURATION WIZARD                    ║
╚════════════════════════════════════════════════════════════════╝
""")
        
        # Main menu
        while True:
            console.print("\n[bold]เลือกการตั้งค่า:[/bold]")
            console.print("  [1] 🤖 ตั้งค่า AI Provider (API Keys)")
            console.print("  [2] 🎯 ตั้งค่า Default Target")
            console.print("  [3] ⚡ ตั้งค่า Rate Limits")
            console.print("  [4] 📊 ดูสถานะการตั้งค่า")
            console.print("  [5] ✅ ตรวจสอบระบบ (Health Check)")
            console.print("  [0] 🚪 ออก")
            
            choice = console.input("\nเลือก [0-5]: ").strip()
            
            if choice == "1":
                self._setup_ai_provider()
            elif choice == "2":
                self._setup_default_target()
            elif choice == "3":
                self._setup_rate_limits()
            elif choice == "4":
                self._show_status()
            elif choice == "5":
                self._health_check()
            elif choice == "0":
                console.print("\n[dim]บันทึกการตั้งค่า...[/dim]")
                break
            else:
                print_warning("กรุณาเลือก 0-5")
    
    def _setup_ai_provider(self) -> None:
        """Setup AI provider and API key."""
        console.print("\n[bold cyan]🤖 AI Provider Setup[/bold cyan]\n")
        
        # Show available providers
        console.print("เลือก AI Provider:\n")
        for i, provider in enumerate(self.AI_PROVIDERS, 1):
            free_badge = "[green]ฟรี[/green]" if provider.is_free else "[yellow]เสียตัง[/yellow]"
            console.print(f"  [{i}] {provider.name}")
            console.print(f"      {free_badge} - {provider.notes}")
            console.print()
        
        choice = console.input("เลือก provider [1-4]: ").strip()
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(self.AI_PROVIDERS):
                provider = self.AI_PROVIDERS[idx]
                self._configure_provider(provider)
            else:
                print_warning("กรุณาเลือก 1-4")
        except ValueError:
            print_warning("กรุณาใส่ตัวเลข")
    
    def _configure_provider(self, provider: AIProviderConfig) -> None:
        """Configure specific provider."""
        console.print(f"\n[bold]{provider.name}[/bold]")
        console.print(f"[dim]สมัครที่: {provider.signup_url}[/dim]\n")
        
        if provider.name == "Ollama (Local)":
            # Ollama special setup
            print_info("Ollama ไม่ต้องใช้ API key")
            console.print("\nติดตั้ง Ollama:")
            console.print("  [cyan]curl -fsSL https://ollama.com/install.sh | sh[/cyan]")
            console.print("  [cyan]ollama pull llama3.1:8b[/cyan]")
            
            # Check if running
            import requests
            try:
                resp = requests.get("http://localhost:11434/api/tags", timeout=2)
                if resp.status_code == 200:
                    print_success("✓ Ollama กำลังรันอยู่!")
                else:
                    print_warning("⚠ Ollama ไม่ตอบสนอง")
            except:
                print_warning("⚠ Ollama ยังไม่ได้เปิด รัน 'ollama serve' ก่อน")
            
            # Save to .env
            self._save_env_var("OLLAMA_URL", "http://localhost:11434")
            return
        
        # Get API key
        current_key = os.getenv(provider.env_key, "")
        masked = f"{current_key[:8]}..." if len(current_key) > 10 else "(ไม่มี)"
        
        console.print(f"API Key ปัจจุบัน: [dim]{masked}[/dim]")
        new_key = console.input(f"ใส่ {provider.env_key} (Enter เพื่อข้าม): ").strip()
        
        if new_key:
            self._save_env_var(provider.env_key, new_key)
            print_success(f"✓ บันทึก {provider.env_key}")
            
            # Test connection
            console.print("[dim]ทดสอบการเชื่อมต่อ...[/dim]")
            if self._test_provider(provider, new_key):
                print_success("✓ เชื่อมต่อสำเร็จ!")
            else:
                print_warning("⚠ เชื่อมต่อไม่สำเร็จ กรุณาตรวจสอบ API key")
        else:
            print_info("ข้ามการตั้งค่า API key")
    
    def _test_provider(self, provider: AIProviderConfig, api_key: str) -> bool:
        """Test provider connection."""
        import requests
        
        try:
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }
            
            # Simple test request
            payload = {
                "model": provider.base_url.split("/")[-1] if "gemini" in provider.base_url else "gpt-4o-mini",
                "messages": [{"role": "user", "content": "Hello"}],
                "max_tokens": 10,
            }
            
            resp = requests.post(
                f"{provider.base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=10,
            )
            
            return resp.status_code == 200
        except Exception as e:
            console.print(f"[dim]Error: {e}[/dim]")
            return False
    
    def _setup_default_target(self) -> None:
        """Setup default target."""
        console.print("\n[bold cyan]🎯 Default Target Setup[/bold cyan]\n")
        
        current = os.getenv("ELENGENIX_DEFAULT_TARGET", "")
        if current:
            console.print(f"เป้าหมายเริ่มต้นปัจจุบัน: [cyan]{current}[/cyan]")
        
        target = console.input("ใส่ default target (เว้นว่างเพื่อลบ): ").strip()
        
        if target:
            self._save_env_var("ELENGENIX_DEFAULT_TARGET", target)
            print_success("✓ บันทึก default target")
        else:
            self._remove_env_var("ELENGENIX_DEFAULT_TARGET")
            print_info("ลบ default target")
    
    def _setup_rate_limits(self) -> None:
        """Setup rate limits."""
        console.print("\n[bold cyan]⚡ Rate Limit Setup[/bold cyan]\n")
        
        current = os.getenv("ELENGENIX_RATE_LIMIT", "5")
        console.print(f"Rate limit ปัจจุบัน: [cyan]{current} req/s[/cyan]")
        console.print("[dim]คำแนะนำ: 5 สำหรับ production, 10 สำหรับ testing[/dim]\n")
        
        limit = console.input("ใส่ rate limit (req/s, Enter เพื่อค่าเดิม): ").strip()
        
        if limit:
            try:
                int(limit)
                self._save_env_var("ELENGENIX_RATE_LIMIT", limit)
                print_success(f"✓ บันทึก rate limit: {limit} req/s")
            except ValueError:
                print_warning("กรุณาใส่ตัวเลข")
    
    def _show_status(self) -> None:
        """Show configuration status."""
        console.print("\n[bold cyan]📊 Configuration Status[/bold cyan]\n")
        
        # AI Providers
        console.print("[bold]🤖 AI Providers:[/bold]")
        for provider in self.AI_PROVIDERS:
            key = os.getenv(provider.env_key, "")
            status = "[green]✓ พร้อมใช้[/green]" if key else "[red]✗ ไม่มี API key[/red]"
            console.print(f"  {provider.name}: {status}")
        
        # Ollama check
        try:
            import requests
            resp = requests.get("http://localhost:11434/api/tags", timeout=2)
            ollama_status = "[green]✓ กำลังรัน[/green]" if resp.status_code == 200 else "[yellow]⚠ ไม่พบ[/yellow]"
        except:
            ollama_status = "[yellow]⚠ ไม่พบ[/yellow]"
        console.print(f"  Ollama (Local): {ollama_status}")
        
        # Active provider
        from tools.universal_ai_client import AIClientManager
        manager = AIClientManager()
        active = manager.get_active_provider()
        console.print(f"\n[bold]Active Provider:[/bold] [cyan]{active}[/cyan]")
        
        # Other settings
        console.print("\n[bold]⚙️ Other Settings:[/bold]")
        default_target = os.getenv("ELENGENIX_DEFAULT_TARGET", "(ไม่มี)")
        rate_limit = os.getenv("ELENGENIX_RATE_LIMIT", "5")
        console.print(f"  Default Target: {default_target}")
        console.print(f"  Rate Limit: {rate_limit} req/s")
        
        # .env file status
        if self.env_file.exists():
            console.print(f"\n[green]✓ .env file มีอยู่[/green]: {self.env_file.absolute()}")
        else:
            console.print(f"\n[yellow]⚠ .env file ยังไม่มี[/yellow]")
    
    def _health_check(self) -> None:
        """Run health check."""
        from tools.doctor import check_health
        check_health()
    
    def _save_env_var(self, key: str, value: str) -> None:
        """Save environment variable to .env file."""
        # Also set in current session
        os.environ[key] = value
        
        # Read existing
        lines = []
        if self.env_file.exists():
            lines = self.env_file.read_text().splitlines()
        
        # Remove existing line with same key
        lines = [l for l in lines if not l.startswith(f"{key}=")]
        
        # Add new line
        lines.append(f"{key}={value}")
        
        # Write back
        self.env_file.write_text("\n".join(lines) + "\n")
    
    def _remove_env_var(self, key: str) -> None:
        """Remove environment variable from .env file."""
        # Remove from current session
        if key in os.environ:
            del os.environ[key]
        
        # Read existing
        if not self.env_file.exists():
            return
        
        lines = self.env_file.read_text().splitlines()
        lines = [l for l in lines if not l.startswith(f"{key}=")]
        self.env_file.write_text("\n".join(lines) + "\n")


def run_config_wizard() -> None:
    """Entry point for configuration wizard."""
    wizard = ConfigWizard()
    wizard.run()
