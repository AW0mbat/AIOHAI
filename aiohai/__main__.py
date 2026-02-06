"""
AIOHAI Entry Point — Run with: python -m aiohai

This is the canonical entry point for AIOHAI. The old entry point
(proxy/aiohai_proxy.py) remains as a backward-compatible wrapper.

Usage:
    python -m aiohai [OPTIONS]

Options will be the same as the current proxy/aiohai_proxy.py CLI.
"""

import sys


def main():
    """Main entry point for AIOHAI."""
    # During refactoring transition, delegate to the old entry point
    # This will be updated in Phase 8 when proxy components are moved
    
    # For now, import and run from the original location
    # This ensures the existing code continues to work during transition
    from aiohai.proxy.orchestrator import main as proxy_main
    return proxy_main()


if __name__ == "__main__":
    sys.exit(main() or 0)
