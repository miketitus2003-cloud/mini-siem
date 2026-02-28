#!/usr/bin/env python3
"""
run.py — Entry point for the Mini SIEM application.

Usage
-----
    # Start with sample data (recommended for first run / demo)
    python run.py --demo

    # Start clean
    python run.py

    # Custom host/port
    python run.py --host 0.0.0.0 --port 8080

    # Enable debug mode
    python run.py --debug
"""

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        description="Mini SIEM — Security Information & Event Management",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind to (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Port to listen on (default: 5000)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable Flask debug mode",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Load sample data on startup (Windows, Linux, Azure)",
    )
    args = parser.parse_args()

    from app import create_app

    app = create_app(load_samples=args.demo)

    print(f"\n{'='*60}")
    print(f"  Mini SIEM Dashboard")
    print(f"  http://{args.host}:{args.port}")
    if args.demo:
        print(f"  Sample data loaded from all sources")
    print(f"{'='*60}\n")

    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
