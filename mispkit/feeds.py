"""Feed health checks.

A MISP fetch job can say "Job done." and still give you nothing useful. In my
build the snort.org ip-block-list feed completed fine and imported exactly two
attributes - a filename and a URL - because the source no longer serves a
plain IP list. Nothing in the UI flags that. These checks do.
"""

from __future__ import annotations

import csv
import io
from collections import Counter
from dataclasses import dataclass, field

from .indicators import detect_type, family_of

OK = "OK"
DEGRADED = "DEGRADED"
BROKEN = "BROKEN"


def looks_like_html(body: str) -> bool:
    head = body.lstrip()[:500].lower()
    return head.startswith("<!doctype html") or head.startswith("<html") or "<head>" in head


def parse_feed(body: str, fmt: str = "freetext", column: int = 0,
               delimiter: str = ",") -> list[str]:
    """Pull candidate indicator values out of a feed body.

    fmt "freetext": one value per line (also splits on whitespace).
    fmt "csv": take `column` (0-based) from each row.
    Lines starting with # or // are treated as comments.
    """
    values: list[str] = []
    if fmt == "csv":
        reader = csv.reader(io.StringIO(body), delimiter=delimiter)
        for row in reader:
            if not row:
                continue
            first = row[0].strip()
            if first.startswith("#") or first.startswith("//"):
                continue
            if len(row) > column:
                cell = row[column].strip().strip('"')
                if cell:
                    values.append(cell)
        return values

    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//") or line.startswith(";"):
            continue
        for token in line.split():
            values.append(token.strip(",;"))
    return values


@dataclass
class FeedReport:
    name: str
    status: str
    total: int
    types: dict[str, int]
    reasons: list[str] = field(default_factory=list)

    def summary(self) -> str:
        mix = ", ".join(f"{k}={v}" for k, v in sorted(self.types.items(), key=lambda kv: -kv[1]))
        lines = [f"{self.status:8} {self.name}: {self.total} values ({mix or 'none'})"]
        lines += [f"         - {r}" for r in self.reasons]
        return "\n".join(lines)


def assess_values(name: str, values: list[str], expect: list[str] | None = None,
                  min_count: int = 1, min_share: float = 0.8) -> FeedReport:
    """Decide whether a list of values is what the feed is supposed to deliver.

    expect: MISP types or families (e.g. ["ip-dst"] or ["md5"]). If given, at
    least `min_share` of the values must belong to those families.
    """
    types = Counter(detect_type(v) for v in values)
    total = len(values)
    reasons: list[str] = []
    status = OK

    if total == 0:
        return FeedReport(name, BROKEN, 0, {}, ["feed returned no indicators"])

    if total < min_count:
        status = DEGRADED
        reasons.append(f"only {total} indicators, expected at least {min_count}")

    if expect:
        families = {family_of(t) for t in expect}
        matching = sum(types[f] for f in families)
        share = matching / total
        if matching == 0:
            status = BROKEN
            reasons.append(
                f"none of the values are {'/'.join(sorted(families))} - the source format "
                "has probably changed")
        elif share < min_share:
            if status == OK:
                status = DEGRADED
            reasons.append(
                f"only {share:.0%} of values are {'/'.join(sorted(families))} "
                f"(threshold {min_share:.0%})")

    return FeedReport(name, status, total, dict(types), reasons)


def assess_body(name: str, body: str, fmt: str = "freetext", column: int = 0,
                expect: list[str] | None = None, min_count: int = 1,
                min_share: float = 0.8) -> FeedReport:
    """Run the checks on a raw feed body (what MISP would download)."""
    if looks_like_html(body):
        return FeedReport(name, BROKEN, 0, {"html": 1},
                          ["source returned an HTML page instead of feed data"])
    values = parse_feed(body, fmt=fmt, column=column)
    return assess_values(name, values, expect=expect, min_count=min_count,
                         min_share=min_share)


def assess_attributes(name: str, attributes: list[dict], expect: list[str] | None = None,
                      min_count: int = 1, min_share: float = 0.8) -> FeedReport:
    """Same idea, but on attributes MISP already imported for a feed event.

    Uses the MISP `type` field rather than guessing from the value.
    """
    total = len(attributes)
    types = Counter(family_of(a.get("type", "unknown")) for a in attributes)
    if total == 0:
        return FeedReport(name, BROKEN, 0, {}, ["feed event has no attributes"])
    report = FeedReport(name, OK, total, dict(types))
    if total < min_count:
        report.status = DEGRADED
        report.reasons.append(f"only {total} attributes, expected at least {min_count}")
    if expect:
        families = {family_of(t) for t in expect}
        matching = sum(types[f] for f in families)
        if matching == 0:
            report.status = BROKEN
            report.reasons.append(
                f"no {'/'.join(sorted(families))} attributes imported - check the source")
        elif matching / total < min_share:
            if report.status == OK:
                report.status = DEGRADED
            report.reasons.append(
                f"only {matching / total:.0%} of attributes are {'/'.join(sorted(families))}")
    return report
