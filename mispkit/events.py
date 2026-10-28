"""Turn a small JSON incident file into a MISP event payload.

Typing seven attributes into the MISP web form by hand is fine once. After
that I wanted the incident written down as a file, linted, and pushed in one
go. See examples/phishing-campaign.json for the format.
"""

from __future__ import annotations

import json
from pathlib import Path

from .indicators import DEFAULT_CATEGORY, detect_type, refang

THREAT_LEVELS = {"high": 1, "medium": 2, "low": 3, "undefined": 4}
ANALYSIS = {"initial": 0, "ongoing": 1, "completed": 2}
DISTRIBUTION = {"organisation": 0, "community": 1, "connected": 2, "all": 3}

# detect_type() family -> MISP type when the file doesn't say
FAMILY_TO_TYPE = {
    "ip": "ip-dst",
    "domain": "domain",
    "url": "url",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "email": "email-src",
    "filename": "filename",
}

NON_IDS_TYPES = {"text", "campaign-name", "comment", "filename"}


def load_incident(path: str | Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if "info" not in data or "indicators" not in data:
        raise ValueError("incident file needs at least 'info' and 'indicators'")
    return data


def build_attribute(item: dict) -> dict:
    value = refang(str(item["value"]))
    misp_type = item.get("type")
    if not misp_type:
        family = detect_type(value)
        misp_type = FAMILY_TO_TYPE.get(family, "text")
    attr = {
        "type": misp_type,
        "category": item.get("category", DEFAULT_CATEGORY.get(misp_type, "Other")),
        "value": value,
        "to_ids": bool(item.get("to_ids", misp_type not in NON_IDS_TYPES)),
        "comment": item.get("comment", ""),
    }
    for key in ("first_seen", "last_seen"):
        if item.get(key):
            attr[key] = item[key]
    return attr


def build_event(incident: dict) -> dict:
    tags = [{"name": t} for t in incident.get("tags", [])]
    event = {
        "info": incident["info"],
        "threat_level_id": THREAT_LEVELS[incident.get("threat_level", "medium")],
        "analysis": ANALYSIS[incident.get("analysis", "initial")],
        "distribution": DISTRIBUTION[incident.get("distribution", "organisation")],
        "published": False,
        "Attribute": [build_attribute(i) for i in incident["indicators"]],
    }
    if incident.get("date"):
        event["date"] = incident["date"]
    if tags:
        event["Tag"] = tags
    return event
