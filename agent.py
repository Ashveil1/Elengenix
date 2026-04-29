"""
agent.py — Elengenix AI Agent Entry Point
Bridge module to initialize and configure ElengenixAgent.
Version: 2.0.0
"""

import logging
from typing import Optional, Dict, Any

# Initialize logger
logger = logging.getLogger("elengenix.agent")

def get_agent(config: Optional[Dict[str, Any]] = None) -> Any:
    """
    Returns an initialized ElengenixAgent instance.

    Args:
        config: Optional dict for dynamic configuration (model, api_key, etc.)

    Returns:
        ElengenixAgent instance

    Raises:
        ImportError: If agent_brain module is missing
        RuntimeError: If agent initialization fails
    """
    try:
        from agent_brain import ElengenixAgent
    except ImportError as e:
        logger.error("Failed to import agent_brain: %s", e)
        raise ImportError("agent_brain.py is missing or corrupted. Please check your installation.") from e

    try:
        if config:
            logger.info("Initializing ElengenixAgent with dynamic configuration...")
            return ElengenixAgent(**config)

        logger.info("Initializing ElengenixAgent with system default config...")
        return ElengenixAgent()

    except Exception as e:
        logger.error("Agent initialization failed: %s", e)
        raise RuntimeError(f"Failed to start Elengenix Agent: {str(e)}") from e

if __name__ == "__main__":
    # Internal Test Block
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    print("[*] Testing Elengenix Agent Bridge...")
    try:
        agent = get_agent()
        print("Agent successfully initialized and ready for mission.")
    except Exception as e:
        print(f"Bridge Test Failed: {e}")
        exit(1)
