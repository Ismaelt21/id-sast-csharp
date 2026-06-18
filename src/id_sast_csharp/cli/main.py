from __future__ import annotations

import argparse
import json

from id_sast_csharp.cli.commands.analysis import run_analysis_stats
from id_sast_csharp.cli.commands.mongo import run_mongo_status
from id_sast_csharp.cli.commands.rules import run_rules_list, run_rules_stats
from id_sast_csharp.cli.commands.scan import run_scan
from id_sast_csharp.infrastructure.config.settings import Settings


def main() -> None:
    Settings.initialize_directories()

    parser = argparse.ArgumentParser(prog="id-sast-csharp")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan a C# project")
    scan_parser.add_argument("path")
    scan_parser.add_argument("--no-ai", action="store_true")
    scan_parser.add_argument("--persist", action="store_true")
    scan_parser.add_argument("--json-only", action="store_true")
    scan_parser.add_argument("--html-only", action="store_true")
    scan_parser.add_argument("--sarif-only", action="store_true")
    scan_parser.add_argument("--output-directory")
    scan_parser.add_argument("--verbose", action="store_true")

    rules_parser = subparsers.add_parser("rules", help="Rules management")
    rules_parser.add_argument("--list", action="store_true")
    rules_parser.add_argument("--stats", action="store_true")

    analysis_parser = subparsers.add_parser("analysis", help="Analysis stats")
    analysis_parser.add_argument("--stats", action="store_true")

    subparsers.add_parser("mongo", help="MongoDB status")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if args.command == "scan":
        result = run_scan(
            args.path,
            use_ai=not args.no_ai,
            verbose=args.verbose,
            persist=args.persist,
            json_only=args.json_only,
            html_only=args.html_only,
            sarif_only=args.sarif_only,
            output_directory=args.output_directory,
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.command == "rules":
        if args.list:
            print(json.dumps(run_rules_list(), indent=2, ensure_ascii=False))
        elif args.stats:
            print(json.dumps(run_rules_stats(), indent=2, ensure_ascii=False))
        else:
            rules_parser.print_help()
    elif args.command == "analysis":
        if args.stats:
            print(json.dumps(run_analysis_stats(), indent=2, ensure_ascii=False))
        else:
            analysis_parser.print_help()
    elif args.command == "mongo":
        print(json.dumps(run_mongo_status(), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
