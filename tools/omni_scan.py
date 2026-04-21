import os
import sys
import subprocess
import asyncio
from rich.console import Console
from rich.panel import Panel

console = Console()

async def run_tool_async(command_list):
    """Runs a security tool asynchronously."""
    process = await asyncio.create_subprocess_exec(
        *command_list,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await process.communicate()
    return stdout.decode().strip()

async def run_omni_scan_optimized(target):
    report_dir = f"reports/{target.replace('.', '_')}"
    os.makedirs(report_dir, exist_ok=True)

    console.print(Panel(f"ELENGENIX OPTIMIZED OMNI-SCAN: {target}", border_style="cyan"))

    # 🏎️ PARALLEL EXECUTION: Dorking and Subdomains at the same time
    console.print("[*] Launching Parallel Recon (Dorking + Subfinder)...")
    
    # Define tasks
    tasks = [
        run_tool_async(["subfinder", "-d", target, "-silent"]),
        # We simulate dorking as an async task here
        asyncio.to_thread(os.system, f"python3 tools/dork_miner.py {target} > /dev/null")
    ]
    
    # Wait for both to finish
    results = await asyncio.gather(*tasks)
    subdomains = results[0]
    
    console.print(f"[green]✅ Parallel Recon Complete. Found {len(subdomains.split())} subdomains.[/green]")

    # Continue with sequential steps for vulnerability scanning (resource intensive)
    # (Rest of the scanning logic follows...)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        asyncio.run(run_omni_scan_optimized(sys.argv[1]))
