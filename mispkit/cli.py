"""Command line entry point: `mispkit lint | push | feed-check | audit`."""

from __future__ import annotations

import argparse
import json
import sys

import requests

from . import __version__
from .client import MispClient, MispError
from .events import build_event, load_incident
from .feeds import BROKEN, OK, assess_attributes, assess_body
from .indicators import lint_indicators


def cmd_lint(args) -> int:
    incident = load_incident(args.file)
    findings = lint_indicators(incident["indicators"])
    for f in findings:
        print(f)
    errors = sum(1 for f in findings if f.level == "error")
    warnings = sum(1 for f in findings if f.level == "warning")
    print(f"\n{len(incident['indicators'])} indicators, {errors} errors, {warnings} warnings")
    if errors or (args.strict and warnings):
        return 1
    return 0


def cmd_push(args) -> int:
    incident = load_incident(args.file)
    findings = lint_indicators(incident["indicators"])
    errors = [f for f in findings if f.level == "error"]
    if errors and not args.force:
        for f in errors:
            print(f)
        print("\nrefusing to push with lint errors (use --force to override)")
        return 1
    event = build_event(incident)
    if args.dry_run:
        print(json.dumps({"Event": event}, indent=2))
        return 0
    client = MispClient.from_env()
    created = client.add_event(event)
    print(f"created event {created.get('id')} - {created.get('info')}")
    return 0


def cmd_feed_check(args) -> int:
    if args.file:
        with open(args.file, encoding="utf-8", errors="replace") as fh:
            body = fh.read()
        name = args.name or args.file
    else:
        resp = requests.get(args.url, timeout=30,
                            headers={"User-Agent": f"mispkit/{__version__}"})
        resp.raise_for_status()
        body = resp.text
        name = args.name or args.url
    report = assess_body(name, body, fmt=args.format, column=args.column,
                         expect=args.expect, min_count=args.min, min_share=args.share)
    print(report.summary())
    return 0 if report.status == OK else (2 if report.status == BROKEN else 1)


def cmd_audit(args) -> int:
    rules = {}
    if args.rules:
        with open(args.rules, encoding="utf-8") as fh:
            rules = json.load(fh)
    client = MispClient.from_env()
    worst = 0
    for feed in client.feeds():
        if feed.get("enabled") not in (True, "1", 1):
            continue
        event_id = feed.get("event_id")
        name = feed.get("name", f"feed {feed.get('id')}")
        if not event_id or str(event_id) == "0":
            print(f"SKIP     {name}: no fixed event (MISP-format feed)")
            continue
        rule = rules.get(str(feed.get("id"))) or rules.get(name) or {}
        event = client.event(event_id)
        report = assess_attributes(name, event.get("Attribute", []),
                                   expect=rule.get("expect"),
                                   min_count=rule.get("min", 1))
        print(report.summary())
        worst = max(worst, {"OK": 0, "DEGRADED": 1, "BROKEN": 2}[report.status])
    return worst


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mispkit", description=__doc__)
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("lint", help="check an incident file before it goes into MISP")
    s.add_argument("file")
    s.add_argument("--strict", action="store_true", help="treat warnings as failures")
    s.set_defaults(func=cmd_lint)

    s = sub.add_parser("push", help="create a MISP event from an incident file")
    s.add_argument("file")
    s.add_argument("--dry-run", action="store_true", help="print the payload, don't send it")
    s.add_argument("--force", action="store_true", help="push even with lint errors")
    s.set_defaults(func=cmd_push)

    s = sub.add_parser("feed-check", help="check a feed source before enabling it")
    src = s.add_mutually_exclusive_group(required=True)
    src.add_argument("--url")
    src.add_argument("--file")
    s.add_argument("--name")
    s.add_argument("--format", choices=["freetext", "csv"], default="freetext")
    s.add_argument("--column", type=int, default=0, help="csv column (0-based)")
    s.add_argument("--expect", nargs="+", help="expected MISP types, e.g. ip-dst md5")
    s.add_argument("--min", type=int, default=1, help="minimum indicator count")
    s.add_argument("--share", type=float, default=0.8,
                   help="minimum share of values matching --expect")
    s.set_defaults(func=cmd_feed_check)

    s = sub.add_parser("audit", help="check what enabled feeds actually imported")
    s.add_argument("--rules", help="JSON file of per-feed expectations")
    s.set_defaults(func=cmd_audit)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (MispError, requests.RequestException, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
