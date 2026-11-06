import os
import sys

# Ensure project root is on sys.path for test imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Keep the suite hermetic: any lazy LLM path (finding-verification engine,
# reasoning phase, ...) must fail fast during tests. Redirect the local
# provider's REQUEST endpoint to a dead port so provider calls get an instant
# connection refused — regardless of whether Ollama is actually running on
# the dev box (without this, a running local Ollama makes every test
# ScanLoop's lazy AIClientManager() hit the live model, tens of seconds per
# call). The verification engine then takes its normal no-LLM fallback path,
# which is what the test suite is written against. dotenv never overrides
# pre-set env vars, so these win over any .env.
os.environ.setdefault("OLLAMA_URL", "http://127.0.0.1:9")
os.environ.setdefault("OLLAMA_BASE_URL", "http://127.0.0.1:9")
