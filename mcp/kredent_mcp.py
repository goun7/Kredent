"""Standalone runner for the Kredent MCP server (see kredent/mcp_server.py)."""
import runpy, sys
from pathlib import Path

# This script lives in <root>/mcp/, so the project root is its parent.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

runpy.run_module("kredent.mcp_server", run_name="__main__")
