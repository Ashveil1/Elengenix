import subprocess
import os
import shutil
import logging

logger = logging.getLogger(__name__)

def run_subdomain_enum(domain, output_dir):
    """
    Performs real subdomain discovery using subfinder and validates with httpx.
    """
    print(f"[*] Starting Real Subdomain Enumeration for: {domain}")
    
    os.makedirs(output_dir, exist_ok=True)
    subfinder_out = os.path.join(output_dir, f"{domain}_subs.txt")
    live_output = os.path.join(output_dir, f"{domain}_live.txt")

    # 1. Subfinder Execution
    if shutil.which("subfinder"):
        try:
            print("[*] Running subfinder...")
            subprocess.run(
                ["subfinder", "-d", domain, "-o", subfinder_out, "-silent"],
                check=True,
                capture_output=True
            )
        except subprocess.CalledProcessError as e:
            logger.error(f"Subfinder failed: {e}")
            with open(subfinder_out, "w") as f: f.write(domain)
    else:
        print("[!] subfinder not found, using main domain only.")
        with open(subfinder_out, "w") as f: f.write(domain)

    # 2. Httpx Validation (Real logic)
    if shutil.which("httpx"):
        try:
            print("[*] Validating live hosts with httpx...")
            with open(subfinder_out, "r") as f_in, open(live_output, "w") as f_out:
                subprocess.run(
                    ["httpx", "-silent", "-status-code", "-title", "-no-color"],
                    stdin=f_in,
                    stdout=f_out,
                    check=True
                )
            return live_output
        except subprocess.CalledProcessError as e:
            logger.error(f"httpx failed: {e}")
            return subfinder_out
    else:
        print("[!] httpx not found, skipping validation.")
        return subfinder_out

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        run_subdomain_enum(sys.argv[1], "reports/test")
