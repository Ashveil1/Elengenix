import subprocess
import shlex
import os
import logging

logger = logging.getLogger(__name__)

ALLOWED_BINARIES = [
    "nmap", "curl", "subfinder", "nuclei", "httpx", 
    "katana", "waybackurls", "ffuf", "python3"
]

def execute_safely(command_str, timeout=300):
    """
    Executes a shell command with strict allowlisting and no shell=True.
    """
    try:
        args = shlex.split(command_str)
        if not args:
            return "Error: Empty command."
        
        binary = os.path.basename(args[0])
        if binary not in ALLOWED_BINARIES:
            return f"Error: Command '{binary}' is not in the security allowlist."

        # Execute without shell=True for security
        result = subprocess.run(
            args,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode
        }

    except subprocess.TimeoutExpired:
        return "Error: Command timed out."
    except Exception as e:
        logger.error(f"Safe execution error: {e}")
        return f"Error: {str(e)}"
