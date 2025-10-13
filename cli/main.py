from __future__ import annotations

import argparse
import asyncio
import sys

from scanner.orchestrator import run_scan
from scanner.config import load_config
from scanner.severity import Policy


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    parser = argparse.ArgumentParser(prog="scanner", description="Web Vulnerability Scanner")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="Run a scan from a YAML config")
    p_scan.add_argument("-c", "--config", required=True, help="Path to config YAML")
    p_scan.add_argument("--fail-on", choices=["Low","Medium","High","Critical"], help="Fail the run if any finding meets this severity or higher")

    args = parser.parse_args(argv)

    if args.cmd == "scan":
        res = asyncio.run(run_scan(args.config))
        print(f"Artifacts: {res['artifact_dir']} | URLs: {res['url_count']} | Findings: {res['findings_count']}")
        # Determine fail-on threshold from CLI or config
        cfg = load_config(args.config)
        threshold = args.fail_on or cfg.ci.fail_on
        if threshold:
            policy = Policy.from_value(threshold)
            should_fail = policy.should_fail(res.get("findings", []))
            if should_fail:
                print(f"Failing due to severity threshold: {threshold}")
                return 2
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
