import os
import asyncio
import logging
from rich.console import Console
from rich.panel import Panel
from tools.context_compressor import compress_output
from bot_utils import send_telegram_notification

console = Console()
logger = logging.getLogger(__name__)

class ScanManager:
    """
    Handles memory-efficient parallel execution of security tools.
    """
    async def run_tool_async(self, cmd_list: list, tool_name: str) -> str:
        console.print(f"[bold cyan][*] Launching {tool_name}...[/bold cyan]")
        try:
            # 🚀 STREAMING: Use communicate() with small chunks or line-by-line reading
            process = await asyncio.create_subprocess_exec(
                *cmd_list,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Read stdout line by line to prevent memory bloat (Ideal for 4GB RAM)
            full_output = []
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                decoded_line = line.decode().strip()
                if decoded_line:
                    full_output.append(decoded_line)
                    # Show progress for long tools
                    if len(full_output) % 50 == 0:
                        console.print(f"[dim]  [{tool_name}] processed {len(full_output)} lines...[/dim]")

            raw_result = "\n".join(full_output)
            return compress_output(raw_result, tool_name)

        except Exception as e:
            logger.error(f"Execution failure for {tool_name}: {e}")
            return f"Error: {e}"

async def run_standard_scan(target: str):
    manager = ScanManager()
    # (Existing chaining logic...)
    await manager.run_tool_async(["subfinder", "-d", target, "-silent"], "Subfinder")
    return "reports"
