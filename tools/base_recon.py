import subprocess
import os
import shutil

def run_subdomain_enum(domain, output_dir):
    """
    Real-world reconnaissance: Subfinder + Waybackurls + Httpx
    """
    print(f"[*] Executing Professional Recon on: {domain}")
    os.makedirs(output_dir, exist_ok=True)
    
    all_subs_file = os.path.join(output_dir, f"{domain}_all_subs.txt")
    live_output = os.path.join(output_dir, f"{domain}_live.txt")

    # 1. Subdomain Discovery (Subfinder)
    if shutil.which("subfinder"):
        print("[*] Gathering subdomains...")
        subprocess.run(["subfinder", "-d", domain, "-o", all_subs_file, "-silent"], capture_output=True)
    else:
        with open(all_subs_file, "w") as f: f.write(domain)

    # 2. Historical URL Discovery (Waybackurls) - This finds hidden gems!
    if shutil.which("waybackurls"):
        print("[*] Fetching historical URLs from Wayback Machine...")
        with open(all_subs_file, "a") as f:
            proc = subprocess.run(["waybackurls", domain], capture_output=True, text=True)
            f.write(proc.stdout)

    # 3. Live Host & Tech Discovery (Httpx)
    if shutil.which("httpx"):
        print("[*] Validating live targets and detecting technology...")
        # Use stdin to avoid 'too many arguments' error
        with open(all_subs_file, "r") as f_in, open(live_output, "w") as f_out:
            subprocess.run(["httpx", "-silent", "-no-color", "-fc", "404"], 
                           stdin=f_in, stdout=f_out)
        return live_output
    
    return all_subs_file

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        run_subdomain_enum(sys.argv[1], "reports/test")
