import json
from pathlib import Path

import pytest

from mispkit import cli
from mispkit.client import MispClient, MispError
from mispkit.events import build_event, load_incident

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "phishing-campaign.json"


def test_build_event_from_example():
    event = build_event(load_incident(EXAMPLE))
    assert event["threat_level_id"] == 1
    assert event["analysis"] == 2
    assert event["distribution"] == 0
    assert event["published"] is False
    values = {a["value"]: a for a in event["Attribute"]}
    # defanged values are stored refanged
    assert "secure-login-example.test" in values
    assert "https://secure-login-example.test/owa/auth" in values
    assert values["203.0.113.25"]["first_seen"] == "2026-09-28T09:15:00Z"
    assert values["203.0.113.25"]["category"] == "Network activity"
    assert values["LAB-Phishing-Campaign"]["to_ids"] is False
    assert values["invoice_Q3.pdf.lnk"]["to_ids"] is False
    assert {"name": "tlp:amber"} in event["Tag"]


def test_type_is_inferred_when_missing():
    event = build_event({"info": "x", "indicators": [{"value": "8.8.8.8"},
                                                      {"value": "a" * 64}]})
    assert [a["type"] for a in event["Attribute"]] == ["ip-dst", "sha256"]


def test_load_incident_requires_fields(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{}")
    with pytest.raises(ValueError):
        load_incident(p)


def write_incident(tmp_path, indicators):
    p = tmp_path / "incident.json"
    p.write_text(json.dumps({"info": "test", "indicators": indicators}))
    return str(p)


def test_cli_lint_example_passes_but_warns(capsys):
    # the example uses documentation IPs and .test domains on purpose
    assert cli.main(["lint", str(EXAMPLE)]) == 0
    assert cli.main(["lint", "--strict", str(EXAMPLE)]) == 1
    out = capsys.readouterr().out
    assert "documentation range" in out


def test_cli_lint_blocks_empty_file_hash(tmp_path, capsys):
    path = write_incident(tmp_path, [{"value": "d41d8cd98f00b204e9800998ecf8427e",
                                      "type": "md5"}])
    assert cli.main(["lint", path]) == 1
    assert "empty file" in capsys.readouterr().out


def test_cli_push_refuses_on_errors(tmp_path):
    path = write_incident(tmp_path, [{"value": "d41d8cd98f00b204e9800998ecf8427e",
                                      "type": "md5"}])
    assert cli.main(["push", path]) == 1


def test_cli_push_dry_run(tmp_path, capsys):
    path = write_incident(tmp_path, [{"value": "1.161.151.139", "type": "ip-dst"}])
    assert cli.main(["push", "--dry-run", path]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["Event"]["Attribute"][0]["value"] == "1.161.151.139"


def test_cli_feed_check_file(tmp_path):
    f = tmp_path / "feed.txt"
    f.write_text("ip-block-list.txt\nhttps://www.snort.org/downloads\n")
    assert cli.main(["feed-check", "--file", str(f), "--expect", "ip-dst"]) == 2
    f.write_text("\n".join(f"1.2.3.{i}" for i in range(20)))
    assert cli.main(["feed-check", "--file", str(f), "--expect", "ip-dst"]) == 0


class FakeResponse:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, routes):
        self.routes = routes
        self.headers = {}
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        for suffix, resp in self.routes.items():
            if url.endswith(suffix):
                return resp
        return FakeResponse(404, {"message": "not found"})


def test_client_sets_auth_header_and_parses_feeds():
    session = FakeSession({"/feeds/index": FakeResponse(200, [{"Feed": {"id": "9"}}])})
    client = MispClient("https://misp.local/", "secret-key", session=session)
    assert client.feeds() == [{"id": "9"}]
    assert session.headers["Authorization"] == "secret-key"
    assert session.calls[0][1] == "https://misp.local/feeds/index"


def test_client_error_does_not_leak_key():
    session = FakeSession({})
    client = MispClient("https://misp.local", "secret-key", session=session)
    with pytest.raises(MispError) as exc:
        client.event(1)
    assert "secret-key" not in str(exc.value)


def test_client_requires_url_and_key():
    with pytest.raises(MispError):
        MispClient("", "")


def test_audit_flags_snort_feed(monkeypatch, tmp_path, capsys):
    feeds = [
        {"Feed": {"id": "6", "name": "Tor ALL nodes", "enabled": True, "event_id": "82"}},
        {"Feed": {"id": "9", "name": "ip-block-list - snort.org", "enabled": True,
                  "event_id": "83"}},
        {"Feed": {"id": "1", "name": "CIRCL OSINT Feed", "enabled": True, "event_id": "0"}},
        {"Feed": {"id": "7", "name": "disabled", "enabled": False, "event_id": "90"}},
    ]
    session = FakeSession({
        "/feeds/index": FakeResponse(200, feeds),
        "/events/view/82": FakeResponse(200, {"Event": {"Attribute": [
            {"type": "ip-dst", "value": f"1.2.3.{i}"} for i in range(5)]}}),
        "/events/view/83": FakeResponse(200, {"Event": {"Attribute": [
            {"type": "filename", "value": "ip-block-list"},
            {"type": "url", "value": "https://snort.org"}]}}),
    })
    monkeypatch.setattr(MispClient, "from_env",
                        classmethod(lambda cls: MispClient("https://m", "k", session=session)))
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps({"Tor ALL nodes": {"expect": ["ip-dst"], "min": 1},
                                 "9": {"expect": ["ip-dst"], "min": 100}}))
    assert cli.main(["audit", "--rules", str(rules)]) == 2
    out = capsys.readouterr().out
    assert "OK       Tor ALL nodes" in out
    assert "BROKEN   ip-block-list - snort.org" in out
    assert "SKIP     CIRCL OSINT Feed" in out
    assert "disabled" not in out
