import subprocess
import os
import shutil

def run_subdomain_enum(domain, output_dir):
    """
    Professional reconnaissance with automatic de-duplication.
    """
    print(f"[*] Starting Unique Reconnaissance on: {domain}")
    os.makedirs(output_dir, exist_ok=True)
    
    raw_subs_file = os.path.join(output_dir, f"{domain}_raw.txt")
    unique_subs_file = os.path.join(output_dir, f"{domain}_unique.txt")

    # 1. Subdomain Discovery
    if shutil.which("subfinder"):
        subprocess.run(["subfinder", "-d", domain, "-o", raw_subs_file, "-silent"], capture_output=True)
    else:
        with open(raw_subs_file, "w") as f: f.write(domain)

    # 2. Historical Discovery (Append to raw)
    if shutil.which("waybackurls"):
        with open(raw_subs_file, "a") as f:
            proc = subprocess.run(["waybackurls", domain], capture_output=True, text=True)
            f.write(proc.stdout)

    # 3. 🧹 DE-DUPLICATION (Python Native)
    if os.path.exists(raw_subs_file):
        with open(raw_subs_file, "r") as f:
            lines = f.readlines()
        
        # Remove empty lines and duplicates, sort for consistency
        unique_lines = sorted(list(set(line.strip() for line in lines if line.strip())))
        
        with open(unique_subs_file, "w") as f:
            f.write("\n".join(unique_lines))
        
        os.remove(raw_subs_file) # Cleanup raw data
        return unique_subs_file
    
    return raw_subs_file

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        run_subdomain_enum(sys.argv[1], "reports/test")
