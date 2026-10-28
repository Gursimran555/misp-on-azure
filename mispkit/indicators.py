"""Indicator helpers: detect what a value is, refang it, and lint it.

Most of the rules in here come from mistakes I actually made or saw while
running MISP: an MD5 of an empty file that correlated with half the
database, documentation IPs sitting next to real ones, and defanged URLs
pasted straight into an event.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

# Hashes of a zero-byte file. They show up in sandbox reports and copy-paste
# accidents all the time, and in MISP they correlate with everything.
EMPTY_FILE_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e": "md5",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709": "sha1",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "sha256",
}

# RFC 5737 / RFC 3849 documentation ranges. Fine for training data,
# never real attacker infrastructure.
DOC_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
]

# RFC 2606 / RFC 6761 reserved TLDs.
RESERVED_TLDS = {"test", "example", "invalid", "localhost", "local"}

_HEX = re.compile(r"^[0-9a-fA-F]+$")
_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?!-)([a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$"
)
_URL = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://\S+$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$")
_FILENAME = re.compile(r"^[^/\\\s]+\.[a-zA-Z0-9]{1,6}$")

# MISP attribute type -> default category
DEFAULT_CATEGORY = {
    "ip-src": "Network activity",
    "ip-dst": "Network activity",
    "domain": "Network activity",
    "hostname": "Network activity",
    "url": "Network activity",
    "email-src": "Payload delivery",
    "md5": "Payload delivery",
    "sha1": "Payload delivery",
    "sha256": "Payload delivery",
    "filename": "Payload delivery",
    "text": "Other",
    "campaign-name": "Attribution",
}

IP_TYPES = {"ip-src", "ip-dst"}
HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}


def refang(value: str) -> str:
    """Undo the usual defanging: hxxp, [.], (.), [:], [@]."""
    v = value.strip()
    v = re.sub(r"^hxxp", "http", v, flags=re.IGNORECASE)
    v = re.sub(r"^fxp", "ftp", v, flags=re.IGNORECASE)
    for fanged, plain in (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."),
                          ("[:]", ":"), ("[@]", "@"), ("[at]", "@")):
        v = v.replace(fanged, plain)
    return v


def defang(value: str) -> str:
    """Make a URL/domain/IP safe to paste into a report or chat."""
    v = re.sub(r"^http", "hxxp", value, flags=re.IGNORECASE)
    return v.replace(".", "[.]")


def detect_type(value: str) -> str:
    """Best guess at the MISP attribute family for a raw value.

    Returns one of: ip, url, domain, md5, sha1, sha256, email, filename, unknown.
    """
    v = refang(value)
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if _HEX.match(v):
        for name, length in HASH_LENGTHS.items():
            if len(v) == length:
                return name
    if _URL.match(v):
        return "url"
    if _EMAIL.match(v):
        return "email"
    if _DOMAIN.match(v):
        # "invoice.pdf" also matches the domain pattern; a short list of
        # common file extensions keeps those out.
        if v.rsplit(".", 1)[-1].lower() in {"exe", "dll", "pdf", "doc", "docx", "xls",
                                              "xlsx", "zip", "rar", "js", "vbs", "ps1",
                                              "bat", "lnk", "iso", "txt", "csv", "gz"}:
            return "filename"
        return "domain"
    if _FILENAME.match(v):
        return "filename"
    return "unknown"


def family_of(misp_type: str) -> str:
    """Map a MISP attribute type to the family detect_type() returns."""
    if misp_type in IP_TYPES:
        return "ip"
    if misp_type in ("domain", "hostname"):
        return "domain"
    if misp_type.startswith("email"):
        return "email"
    return misp_type


@dataclass
class Finding:
    level: str  # "error", "warning" or "info"
    value: str
    message: str

    def __str__(self) -> str:
        return f"[{self.level.upper():7}] {self.value}: {self.message}"


def lint_indicator(value: str, misp_type: str | None = None) -> list[Finding]:
    """Check a single indicator. Errors should block an import."""
    findings: list[Finding] = []
    raw = value.strip()
    v = refang(raw)

    if not v:
        return [Finding("error", raw, "empty value")]

    if v != raw:
        findings.append(Finding("info", raw, f"was defanged, will be stored as {v}"))

    detected = detect_type(v)

    if misp_type and misp_type not in ("text", "campaign-name", "comment"):
        expected = family_of(misp_type)
        if detected != "unknown" and expected != detected:
            findings.append(Finding(
                "error", raw, f"declared as {misp_type} but looks like {detected}"))
        if misp_type in HASH_LENGTHS and len(v) != HASH_LENGTHS[misp_type]:
            findings.append(Finding(
                "error", raw,
                f"{misp_type} must be {HASH_LENGTHS[misp_type]} hex chars, got {len(v)}"))

    if v.lower() in EMPTY_FILE_HASHES:
        findings.append(Finding(
            "error", raw,
            f"{EMPTY_FILE_HASHES[v.lower()]} of an empty file - it will correlate with "
            "every event that contains it"))

    if detected == "ip":
        ip = ipaddress.ip_address(v)
        if any(ip in net for net in DOC_NETWORKS):
            findings.append(Finding(
                "warning", raw, "documentation range (RFC 5737/3849) - test data, not real intel"))
        elif ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
            findings.append(Finding(
                "warning", raw, "private/reserved address - should not be shared as an IOC"))

    if detected in ("domain", "url", "email"):
        host = v
        if detected == "url":
            host = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", v).split("/")[0].split(":")[0]
        elif detected == "email":
            host = v.split("@", 1)[1]
        tld = host.rsplit(".", 1)[-1].lower()
        if tld in RESERVED_TLDS:
            findings.append(Finding("warning", raw, f"reserved TLD .{tld} - test data"))

    return findings


def lint_indicators(items: list[dict]) -> list[Finding]:
    """Lint a list of {"value": ..., "type": ...} dicts, including duplicates."""
    findings: list[Finding] = []
    seen: dict[str, int] = {}
    for item in items:
        value = str(item.get("value", ""))
        findings.extend(lint_indicator(value, item.get("type")))
        key = refang(value).lower()
        seen[key] = seen.get(key, 0) + 1
    for key, count in seen.items():
        if key and count > 1:
            findings.append(Finding("warning", key, f"appears {count} times"))
    return findings
