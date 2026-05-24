import subprocess
import time
import hashlib
from pathlib import Path
from .governance import Governance

class ShellExecutor:
    """Executes shell commands on the host system, enforces safety rules, and archives raw logs."""
    
    def __init__(self, log_dir: str = "logs"):
        self.governance = Governance()
        self.log_dir = Path(log_dir)
        self.raw_log_dir = self.log_dir / "raw"
        self.raw_log_dir.mkdir(parents=True, exist_ok=True)

    def execute(self, command: str, timeout: int = 300) -> dict:
        """
        Verify the command, execute it if permitted, write the full output to logs, 
        and return a compact summary.
        """
        # Safety gate check
        if not self.governance.verify_and_prompt(command):
            return {
                "success": False,
                "exit_code": -1,
                "error": "Execution blocked by governance policy.",
                "stdout_summary": "",
                "stderr_summary": "",
                "log_path": None
            }

        start_time = time.time()
        
        try:
            # If command requires sudo, prompt interactively first to cache credentials
            if "sudo " in command:
                print("\n[System] Command requires sudo. Please enter your password if prompted:")
                try:
                    subprocess.run("sudo -v", shell=True, check=True)
                except subprocess.CalledProcessError:
                    return {
                        "success": False,
                        "exit_code": -4,
                        "error": "Sudo authentication failed or was cancelled.",
                        "stdout_summary": "",
                        "stderr_summary": "",
                        "log_path": None
                    }

            # Run the command directly on shell
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            duration = time.time() - start_time
            
            # Create a unique filename for the log based on timestamp and command hash
            cmd_hash = hashlib.md5(command.encode('utf-8')).hexdigest()[:8]
            timestamp = int(start_time)
            log_file = self.raw_log_dir / f"cmd_{timestamp}_{cmd_hash}.log"
            
            # Write full log
            log_content = (
                f"Command: {command}\n"
                f"Timestamp: {start_time}\n"
                f"Exit Code: {result.returncode}\n"
                f"Duration: {duration:.2f}s\n"
                f"--- STDOUT ---\n{result.stdout}\n"
                f"--- STDERR ---\n{result.stderr}\n"
            )
            log_file.write_text(log_content, encoding="utf-8")
            
            # Extract compact summaries for context retention
            stdout_summary = result.stdout[:1000]
            if len(result.stdout) > 1000:
                stdout_summary += f"\n... [Truncated: full output at {log_file}]"
                
            stderr_summary = result.stderr[:500]
            if len(result.stderr) > 500:
                stderr_summary += f"\n... [Truncated: full output at {log_file}]"

            return {
                "success": result.returncode == 0,
                "exit_code": result.returncode,
                "error": "",
                "stdout_summary": stdout_summary,
                "stderr_summary": stderr_summary,
                "log_path": str(log_file.resolve())
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "exit_code": -2,
                "error": f"Command timed out after {timeout} seconds.",
                "stdout_summary": "",
                "stderr_summary": "",
                "log_path": None
            }
        except KeyboardInterrupt:
            print("\n[System] Command execution interrupted by user (Ctrl+C).")
            return {
                "success": False,
                "exit_code": -5,
                "error": "Execution aborted by user (Ctrl+C).",
                "stdout_summary": "",
                "stderr_summary": "",
                "log_path": None
            }
        except Exception as e:
            return {
                "success": False,
                "exit_code": -3,
                "error": f"Execution error: {str(e)}",
                "stdout_summary": "",
                "stderr_summary": "",
                "log_path": None
            }
