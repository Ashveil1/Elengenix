"""
agent.py — Elengenix AI Agent Entry Point
Bridge module to initialize and configure ElengenixAgent.
Version: 1.0.0
"""

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("elengenix.agent")

_agent_instance = None


def get_agent(config: Optional[Dict[str, Any]] = None) -> Any:
    """
    Returns an initialized ElengenixAgent instance (cached).

    Args:
        config: Optional dict for dynamic configuration (model, api_key, etc.)

    Returns:
        ElengenixAgent instance
    """
    global _agent_instance
    if _agent_instance is not None and config is None:
        return _agent_instance

    try:
        from core.brain import ElengenixAgent
    except ImportError as e:
        logger.error("Failed to import agent_brain: %s", e)
        raise ImportError(
            "agent_brain.py is missing or corrupted. Please check your installation."
        ) from e

    try:
        if config:
            logger.info("Initializing ElengenixAgent with dynamic configuration...")
            _agent_instance = ElengenixAgent(**config)
        else:
            logger.info("Initializing ElengenixAgent with system default config...")
            _agent_instance = ElengenixAgent()
        return _agent_instance
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
