import subprocess
import os

def run_subdomain_enum(domain, output_dir):
    print(f"[*] Starting Subdomain Enumeration for: {domain}")
    output_file = os.path.join(output_dir, f"{domain}_subs.txt")
    live_output = os.path.join(output_dir, f"{domain}_live.txt")
    
    # 🎯 Force write the target to ensure we always have something to scan
    with open(output_file, "w") as f:
        f.write(domain + "\n")
    
    # Try to clean domain for direct URL
    target_url = domain
    if not target_url.startswith("http"):
        target_url = f"https://{target_url}"

    with open(live_output, "w") as f:
        f.write(target_url + "\n")
        
    print(f"✅ Target prepared: {target_url}")
    return live_output
