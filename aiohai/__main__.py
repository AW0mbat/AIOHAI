"""
AIOHAI Entry Point — Run with: python -m aiohai

This is the canonical (and only) entry point for AIOHAI.

Usage:
    python -m aiohai [OPTIONS]

Options:
    --no-hsm        Start without Nitrokey HSM hardware
    --no-fido2      Start without FIDO2 hardware key approval
    --hsm-pin PIN   Provide HSM PIN on command line
    --hsm-optional  Allow startup without HSM connected
"""

import sys


def main():
    """Main entry point for AIOHAI."""
    from aiohai.proxy.orchestrator import main as proxy_main
    return proxy_main()


if __name__ == "__main__":
    sys.exit(main() or 0)
