import subprocess
import os

def run_nuclei_scan(target_file, output_dir, severity="low,medium,high,critical"):
    """
    Standard vulnerability scan using nuclei.
    """
    print(f"[*] Starting Nuclei Scan for targets in: {target_file}")
    output_file = os.path.join(output_dir, "nuclei_results.txt")
    
    try:
        cmd = [
            "nuclei", 
            "-l", target_file, 
            "-o", output_file, 
            "-severity", severity,
            "-silent"
        ]
        subprocess.run(cmd, check=True)
        return output_file
    except Exception as e:
        return f"Error during scanning: {str(e)}"
