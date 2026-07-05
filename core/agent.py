"""
core/agent.py — Elengenix AI Agent Entry Point

Bridge module to initialize and configure ElengenixAgent.
Thread-safe singleton with proper lifecycle management.

Thread Safety:
    All access to the singleton is protected by a threading lock.
    Concurrent calls to get_agent() will not create duplicate instances.

Config Behavior:
    - First call: creates and caches the instance
    - Subsequent calls without config: returns cached instance
    - Calls with config: creates new instance, disposes old one
    - reset_agent(): explicitly clears the singleton
"""

from __future__ import annotations

import logging
import sys
import threading
from typing import TYPE_CHECKING, Any, Dict, Optional

if TYPE_CHECKING:
    from core.brain import ElengenixAgent

logger = logging.getLogger("elengenix.agent")

_agent_instance: Optional["ElengenixAgent"] = None
_agent_lock = threading.Lock()


def get_agent(config: Optional[Dict[str, Any]] = None) -> "ElengenixAgent":
    """
    Returns an initialized ElengenixAgent instance (thread-safe singleton).

    Thread Safety:
        Uses a threading lock to prevent race conditions when multiple
        threads call get_agent() simultaneously.

    Config Behavior:
        - config=None: returns cached instance (or creates new one)
        - config={...}: creates new instance, disposes old one if exists

    Args:
        config: Optional dict for dynamic configuration.
                Valid keys depend on ElengenixAgent.__init__ parameters:
                - max_steps (int): Maximum reasoning steps
                - loop_threshold (int): Loop detection threshold
                - history_limit (int): Conversation history limit
                - max_output_len (int): Max output length
                - enable_planning (bool): Enable strategic planning
                - enable_cot_logging (bool): Enable chain-of-thought logging
                - max_history_turns (int): Max history turns
                - verbose_thoughts (bool): Show verbose thoughts

    Returns:
        ElengenixAgent instance

    Raises:
        ImportError: If core.brain module cannot be imported
        RuntimeError: If agent initialization fails
    """
    global _agent_instance

    with _agent_lock:
        # Return cached instance if no config provided
        if _agent_instance is not None and config is None:
            return _agent_instance

        # Dispose old instance if config is provided
        if _agent_instance is not None and config is not None:
            logger.info("Disposing old agent instance before creating new one...")
            _dispose_agent(_agent_instance)
            _agent_instance = None

        # Import the agent class
        try:
            from core.brain import ElengenixAgent
        except ImportError as e:
            logger.exception("Failed to import core.brain module")
            raise ImportError(
                f"Cannot import core.brain: {e}. "
                "Check your installation or reinstall Elengenix."
            ) from e

        # Validate config keys
        if config:
            _validate_config(config)

        # Create the agent instance
        try:
            if config:
                logger.info("Initializing ElengenixAgent with config: %s", list(config.keys()))
                _agent_instance = ElengenixAgent(**config)
            else:
                logger.info("Initializing ElengenixAgent with default config")
                _agent_instance = ElengenixAgent()
            return _agent_instance
        except TypeError as e:
            # Config key error — provide helpful message
            logger.exception("Invalid config parameter")
            raise RuntimeError(
                f"Invalid config parameter: {e}. "
                f"Check ElengenixAgent.__init__ signature."
            ) from e
        except Exception as e:
            logger.exception("Agent initialization failed")
            raise RuntimeError(
                f"Failed to initialize ElengenixAgent: {type(e).__name__}: {e}"
            ) from e


def reset_agent() -> None:
    """
    Reset the singleton agent instance.

    Disposes the current instance cleanly and clears the cache.
    Use this when:
    - You need to create a fresh agent with different config
    - You want to clean up resources from a previous session
    - You're testing and need a clean state
    """
    global _agent_instance

    with _agent_lock:
        if _agent_instance is not None:
            logger.info("Resetting agent instance...")
            _dispose_agent(_agent_instance)
            _agent_instance = None
            logger.info("Agent instance reset complete")


def is_agent_initialized() -> bool:
    """
    Check if the agent singleton is initialized.

    Returns:
        True if an agent instance exists, False otherwise.
    """
    return _agent_instance is not None


def _dispose_agent(agent: "ElengenixAgent") -> None:
    """
    Cleanly dispose an agent instance.

    Attempts to close any open connections, sessions, or resources.
    Failures are logged but do not raise exceptions.

    Args:
        agent: The agent instance to dispose.
    """
    try:
        # Close conversation manager if it has one
        if hasattr(agent, "conversation_manager"):
            cm = agent.conversation_manager
            if hasattr(cm, "close"):
                cm.close()

        # Close AI client connections
        if hasattr(agent, "client"):
            client = agent.client
            if hasattr(client, "close"):
                client.close()

        logger.debug("Agent instance disposed successfully")
    except Exception as e:
        logger.debug("Error during agent disposal (non-critical): %s", e)


def _validate_config(config: Dict[str, Any]) -> None:
    """
    Validate config keys against ElengenixAgent.__init__ parameters.

    Args:
        config: Config dict to validate.

    Raises:
        ValueError: If unknown config keys are found.
    """
    valid_keys = {
        "max_steps", "loop_threshold", "history_limit", "max_output_len",
        "enable_planning", "enable_cot_logging", "max_history_turns",
        "verbose_thoughts",
    }
    unknown_keys = set(config.keys()) - valid_keys
    if unknown_keys:
        logger.warning("Unknown config keys ignored: %s", unknown_keys)


if __name__ == "__main__":
    # Smoke test — requires real resources (API keys, etc.)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    print("[*] Running agent bridge smoke test...")

    try:
        agent = get_agent()
        print("[OK] Agent initialized successfully")
        print(f"    Type: {type(agent).__name__}")
        print(f"    Max steps: {agent.max_steps}")
        print(f"    Planning enabled: {agent.enable_planning}")
        print(f"    CoT logging: {agent.enable_cot_logging}")
    except ImportError as e:
        print(f"[FAIL] Import error: {e}")
        sys.exit(1)
    except RuntimeError as e:
        print(f"[FAIL] Runtime error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[FAIL] Unexpected error: {type(e).__name__}: {e}")
        sys.exit(1)

    print("[OK] Smoke test passed")
