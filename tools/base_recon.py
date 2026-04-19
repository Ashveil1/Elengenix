import subprocess
import os

def run_subdomain_enum(domain, output_dir):
    """
    Standard subdomain discovery using subfinder.
    """
    print(f"[*] Starting Subdomain Enumeration for: {domain}")
    output_file = os.path.join(output_dir, f"{domain}_subs.txt")
    
    try:
        # Run subfinder
        cmd = ["subfinder", "-d", domain, "-o", output_file, "-silent"]
        subprocess.run(cmd, check=True)
        
        # Check live targets with httpx
        live_output = os.path.join(output_dir, f"{domain}_live.txt")
        cmd_live = ["httpx", "-l", output_file, "-o", live_output, "-silent", "-status-code", "-title"]
        subprocess.run(cmd_live, check=True)
        
        return live_output
    except Exception as e:
        return f"Error during recon: {str(e)}"

if __name__ == "__main__":
    # Example usage
    import sys
    if len(sys.argv) > 1:
        run_subdomain_enum(sys.argv[1], "reports")
