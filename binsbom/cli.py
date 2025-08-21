
from __future__ import annotations
import argparse, sys, json, pathlib
from .scanner import Scanner
from .sbom import BomWriter


def main() -> None:
    parser = argparse.ArgumentParser(prog="binsbom", description="Scan binaries and emit an SBOM")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="Scan a file or directory")
    p_scan.add_argument("path", type=str, help="File or directory to scan")
    p_scan.add_argument("-o", "--out", type=str, default="-", help="Output file (default: stdout)")
    p_scan.add_argument("--format", choices=["cyclonedx-json"], default="cyclonedx-json", help="SBOM format")

    args = parser.parse_args()
    if args.cmd == "scan":
        path = pathlib.Path(args.path)
        if not path.exists():
            print(f"Path does not exist: {path}", file=sys.stderr)
            sys.exit(2)

        scanner = Scanner()
        findings = scanner.scan_path(path)

        writer = BomWriter(format=args.format)
        bom_json = writer.write(findings=findings, root=str(path.resolve()))

        if args.out == "-" or args.out is None:
            print(bom_json)
        else:
            out_path = pathlib.Path(args.out)
            out_path.write_text(bom_json, encoding="utf-8")
            print(f"SBOM written to {out_path}")
