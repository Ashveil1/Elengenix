import os
import yaml
import questionary
from agent import get_agent
from rich.console import Console
from rich.markdown import Markdown

console = Console()

def main():
    console.print("[bold cyan]🛡️ Elengenix AI Partner Mode (v1.2)[/bold cyan]")
    console.print("[dim]The AI is now capable of autonomous loops (up to 20 steps).[/dim]\n")
    
    # Initialize the Professional Agent
    with console.status("[bold yellow]Initializing AI Brain & Memory...[/bold yellow]"):
        agent = get_agent()

    console.print(f"[bold green]✅ Agent Ready! Memory: SQLite-Powered[/bold green]\n")
    console.print("[dim]Type '/exit' to quit. Ask me to find bugs, research CVEs, or write scripts.[/dim]\n")

    while True:
        try:
            user_input = input("👤 Hunter: ")
            if user_input.lower() == "/exit":
                break
            
            # Helper for displaying agent thoughts in real-time
            def callback(msg):
                console.print(f"[dim]{msg}[/dim]")

            # Run the reasoning loop (Think -> Act -> Observe)
            response = agent.process_query(user_input, callback=callback)
            
            console.print("\n" + "="*30)
            console.print(Markdown(f"🤖 **Sentinel:**\n{response}"))
            console.print("="*30 + "\n")

        except KeyboardInterrupt:
            break
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")

if __name__ == "__main__":
    main()
