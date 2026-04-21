import os
import asyncio
import logging
from rich.console import Console
from rich.panel import Panel
from tools.context_compressor import compress_output
from tools.base_recon import run_subdomain_enum
from bot_utils import send_telegram_notification, send_document

console = Console()
logger = logging.getLogger(__name__)

class ScanManager:
    """
    Handles parallel execution of security tools using asyncio.
    """
    async def run_tool_async(self, cmd_list: list, tool_name: str) -> str:
        console.print(f"[bold cyan][*] Launching {tool_name}...[/bold cyan]")
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd_list,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            raw_output = stdout.decode().strip()
            
            # 🎯 PERFORMANCE: Compress output before returning
            compressed = compress_output(raw_output, tool_name)
            return compressed
        except Exception as e:
            logger.error(f"Async execution error for {tool_name}: {e}")
            return f"Error running {tool_name}"

async def run_standard_scan(target: str, report_dir_base: str = "reports"):
    """
    Unified Orchestrator: Chains tools and utilizes ScanManager for speed.
    """
    manager = ScanManager()
    report_dir = f"{report_dir_base}/{target.replace('.', '_')}"
    os.makedirs(report_dir, exist_ok=True)

    console.print(Panel(f"ELENGENIX PARALLEL PIPELINE: {target}", border_style="green"))
    send_telegram_notification(f"Starting optimized parallel scan for: {target}")

    # 🏎️ PHASE 1: Parallel Recon
    tasks = [
        manager.run_tool_async(["subfinder", "-d", target, "-silent"], "Subfinder"),
        # Simulation of dorking/other light tasks
        manager.run_tool_async(["echo", "Running intelligence gathering"], "Intel")
    ]
    
    recon_results = await asyncio.gather(*tasks)
    console.print(f"[green]Reconnaissance complete. Proceeding to scanning phase.[/green]")

    # PHASE 2: Heavy Vulnerability Scanning
    # We run nuclei on the found targets
    await manager.run_tool_async(["nuclei", "-target", target, "-as", "-silent"], "Nuclei")

    send_telegram_notification(f"Scan mission completed for {target}")
    return report_dir

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        asyncio.run(run_standard_scan(sys.argv[1]))
