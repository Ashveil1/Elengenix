"""
tmux_manager.py — Tmux Session Manager for Split-Screen Experience (v1.0.0)
- Auto-detects if running in tmux
- Creates split windows for chat + logs
- Synchronized log viewing
"""

import os
import sys
import subprocess
import logging
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger("elengenix.tmux")

class TmuxManager:
 """
 Manages tmux sessions for Elengenix split-screen experience.
 Left pane: Chat interface
 Right pane: Live logs / Agent thoughts
 """
 
 SESSION_NAME = "elengenix"
 LOG_WINDOW = "logs"
 CHAT_WINDOW = "chat"
 
 def __init__(self):
 self.in_tmux = self._detect_tmux()
 self.tmux_available = self._check_tmux_installed()
 
 def _detect_tmux(self) -> bool:
 """Check if currently running inside tmux."""
 return os.environ.get("TMUX") is not None
 
 def _check_tmux_installed(self) -> bool:
 """Check if tmux command is available."""
 try:
 subprocess.run(["tmux", "-V"], capture_output=True, check=True)
 return True
 except (subprocess.CalledProcessError, FileNotFoundError):
 return False
 
 def is_available(self) -> bool:
 """Check if tmux features can be used."""
 return self.tmux_available
 
 def create_split_session(self) -> bool:
 """
 Create new tmux session with split windows.
 Left: Chat | Right: Live logs
 """
 if not self.tmux_available:
 logger.warning("Tmux not available")
 return False
 
 # Check if session already exists
 if self._session_exists():
 logger.info(f"Attaching to existing session: {self.SESSION_NAME}")
 self._attach_session()
 return True
 
 try:
 # Get project directory
 project_dir = Path(__file__).parent.absolute()
 
 # Source venv if exists
 venv_python = project_dir / "venv" / "bin" / "python"
 if venv_python.exists():
 python_cmd = str(venv_python)
 else:
 python_cmd = sys.executable
 
 # Create new session with initial window for chat
 chat_command = f"cd {project_dir} && ELENGENIX_IN_TMUX=1 {python_cmd} cli.py"
 
 subprocess.run([
 "tmux", "new-session", "-d", "-s", self.SESSION_NAME,
 "-n", self.CHAT_WINDOW,
 chat_command
 ], check=True)
 
 # Split window vertically (left for chat, right for logs)
 log_command = f"cd {project_dir} && ELENGENIX_IN_TMUX=1 {python_cmd} live_display.py --mode logs"
 subprocess.run([
 "tmux", "split-window", "-h", "-t", f"{self.SESSION_NAME}:{self.CHAT_WINDOW}",
 "-p", "40", # Right pane takes 40% width
 log_command
 ], check=True)
 
 # Attach to session
 self._attach_session()
 return True
 
 except subprocess.CalledProcessError as e:
 logger.error(f"Failed to create tmux session: {e}")
 return False
 
 def _session_exists(self) -> bool:
 """Check if elengenix tmux session exists."""
 try:
 result = subprocess.run(
 ["tmux", "has-session", "-t", self.SESSION_NAME],
 capture_output=True
 )
 return result.returncode == 0
 except:
 return False
 
 def _attach_session(self):
 """Attach to existing tmux session."""
 subprocess.run(["tmux", "attach-session", "-t", self.SESSION_NAME])
 
 def send_to_log_pane(self, message: str):
 """Send message to the log pane."""
 if not self.in_tmux:
 return
 
 try:
 subprocess.run([
 "tmux", "send-keys", "-t", f"{self.SESSION_NAME}:{self.CHAT_WINDOW}.1",
 message, "Enter"
 ], check=False)
 except:
 pass
 
 def get_pane_info(self) -> Tuple[bool, str]:
 """
 Get current pane information.
 Returns: (is_chat_pane, pane_id)
 """
 if not self.in_tmux:
 return (True, "0")
 
 try:
 result = subprocess.run(
 ["tmux", "display-message", "-p", "#I.#P"],
 capture_output=True, text=True
 )
 pane_id = result.stdout.strip()
 # Even panes (0, 2, 4...) are left (chat), odd are right (logs)
 pane_num = int(pane_id.split(".")[-1])
 is_chat = pane_num % 2 == 0
 return (is_chat, pane_id)
 except:
 return (True, "0")
 
 def setup_environment(self):
 """Setup environment variables for tmux integration."""
 if self.in_tmux:
 os.environ["ELENGENIX_IN_TMUX"] = "1"
 is_chat, pane_id = self.get_pane_info()
 os.environ["ELENGENIX_PANE"] = "chat" if is_chat else "logs"
 os.environ["ELENGENIX_PANE_ID"] = pane_id

def get_tmux_manager() -> TmuxManager:
 """Get singleton TmuxManager instance."""
 return TmuxManager()

def launch_tmux_mode():
 """Entry point for launching in tmux split mode."""
 manager = get_tmux_manager()
 
 if not manager.is_available():
 print("Tmux not installed. Install with: apt install tmux")
 return False
 
 if manager.in_tmux:
 print("Already in tmux session")
 return True
 
 return manager.create_split_session()

if __name__ == "__main__":
 if len(sys.argv) > 1 and sys.argv[1] == "--launch":
 success = launch_tmux_mode()
 sys.exit(0 if success else 1)
