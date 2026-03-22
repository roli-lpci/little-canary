"""
little_canary.cli — Command-line interface for Little Canary.

Entry point: ``little-canary`` (installed via pyproject.toml console_scripts).

Sub-commands
------------
serve   Start the persistent HTTP detection server.
"""

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        prog="little-canary",
        description="Prompt injection detection via sacrificial LLM probes",
    )
    subparsers = parser.add_subparsers(dest="command")

    # -- serve --------------------------------------------------------------
    serve_parser = subparsers.add_parser(
        "serve",
        help="Start the persistent HTTP detection server",
    )
    serve_parser.add_argument(
        "--port",
        type=int,
        default=18421,
        help="TCP port to bind on localhost (default: 18421)",
    )
    serve_parser.add_argument(
        "--mode",
        choices=["block", "advisory", "full"],
        default="advisory",
        help="Pipeline mode (default: advisory)",
    )
    serve_parser.add_argument(
        "--canary-model",
        default="qwen2.5:1.5b",
        help="Ollama model tag for the canary probe (default: qwen2.5:1.5b)",
    )

    args = parser.parse_args()

    if args.command == "serve":
        from little_canary.server import run_server

        run_server(
            port=args.port,
            mode=args.mode,
            canary_model=args.canary_model,
        )
    else:
        parser.print_help()
        sys.exit(1)
