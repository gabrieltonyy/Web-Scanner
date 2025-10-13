from __future__ import annotations

import argparse
import asyncio
import sys

from scanner.orchestrator import run_scan


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    parser = argparse.ArgumentParser(prog="scanner", description="Web Vulnerability Scanner")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="Run a scan from a YAML config")
    p_scan.add_argument("-c", "--config", required=True, help="Path to config YAML")

    args = parser.parse_args(argv)

    if args.cmd == "scan":
        res = asyncio.run(run_scan(args.config))
        print(f"Artifacts: {res['artifact_dir']} | URLs: {res['url_count']} | Findings: {res['findings_count']}")
        # Return non-zero later based on severity threshold; for now, 0.
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

