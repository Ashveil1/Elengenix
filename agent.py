"""
agent.py — Elengenix AI Agent Entry Point
This file acts as a bridge to the upgraded agent_brain.py logic.
"""

from agent_brain import ElengenixAgent

def get_agent():
    """
    Returns an instance of the professional Elengenix Agent (v1.2).
    """
    return ElengenixAgent()

if __name__ == "__main__":
    # Test if the agent can be initialized
    print("[*] Initializing Elengenix Agent...")
    agent = get_agent()
    print("✅ Agent ready for duty.")
