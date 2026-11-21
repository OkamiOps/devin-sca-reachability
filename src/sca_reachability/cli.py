import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from sca_reachability.errors import InputError
from sca_reachability.json_io import load_json_file
from sca_reachability.osv import parse_batch_response
from sca_reachability.pipeline import analyze
from sca_reachability.report import build_report
from sca_reachability.sbom import load_components


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sca-reachability",
        description="Analyze local CycloneDX and OSV querybatch JSON files.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze_parser = subparsers.add_parser(
        "analyze", help="analyze a local SBOM against a local OSV response"
    )
    analyze_parser.add_argument("--sbom", required=True, type=Path)
    analyze_parser.add_argument("--osv-response", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        components = load_components(args.sbom)
        response = load_json_file(args.osv_response, "OSV response")
        vulnerabilities = parse_batch_response(response, components)
        result = analyze(components, vulnerabilities)
    except InputError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    print(json.dumps(build_report(result), indent=2, sort_keys=True))
    return 0
