from mispkit.feeds import (BROKEN, DEGRADED, OK, assess_attributes, assess_body,
                           looks_like_html, parse_feed)

TOR_LIKE = "\n".join(f"1.2.3.{i}" for i in range(1, 201))

MALWAREBAZAAR_LIKE = """################################################################
# MalwareBazaar recent malware samples (MD5 hashes)            #
################################################################
33cb0ec1eccfb398abebdc04106729f1
9ad77de41628c60c6cb213390d805c21
"""

# Roughly what came back for the snort.org block list in my build: the job
# finished, and MISP imported one filename and one URL.
SNORT_LIKE = """# Snort IP block list has moved
ip-block-list.txt
https://www.snort.org/downloads
"""


def test_parse_freetext_skips_comments():
    assert parse_feed(MALWAREBAZAAR_LIKE) == [
        "33cb0ec1eccfb398abebdc04106729f1",
        "9ad77de41628c60c6cb213390d805c21",
    ]


def test_parse_csv_column():
    body = '# first_seen,sha256,md5\n"2026-10-02","aaa","33cb0ec1eccfb398abebdc04106729f1"\n'
    assert parse_feed(body, fmt="csv", column=2) == ["33cb0ec1eccfb398abebdc04106729f1"]


def test_healthy_ip_feed():
    report = assess_body("Tor", TOR_LIKE, expect=["ip-dst"], min_count=100)
    assert report.status == OK
    assert report.types == {"ip": 200}


def test_snort_case_is_broken_not_ok():
    report = assess_body("snort", SNORT_LIKE, expect=["ip-dst"], min_count=100)
    assert report.status == BROKEN
    assert any("format" in r for r in report.reasons)


def test_too_few_indicators_is_degraded():
    report = assess_body("bazaar", MALWAREBAZAAR_LIKE, expect=["md5"], min_count=100)
    assert report.status == DEGRADED


def test_mixed_content_below_share_is_degraded():
    body = "\n".join(["1.1.1.1"] * 6 + ["evil.com"] * 4)
    report = assess_body("mixed", body, expect=["ip-dst"], min_share=0.8)
    assert report.status == DEGRADED


def test_html_instead_of_feed():
    body = "<!DOCTYPE html><html><head><title>Moved</title></head></html>"
    assert looks_like_html(body)
    assert assess_body("x", body).status == BROKEN


def test_empty_feed_is_broken():
    assert assess_body("x", "# nothing here\n").status == BROKEN


def test_assess_attributes_uses_misp_types():
    attrs = [{"type": "filename", "value": "ip-block-list"},
             {"type": "url", "value": "https://snort.org/downloads"}]
    report = assess_attributes("snort", attrs, expect=["ip-dst"], min_count=100)
    assert report.status == BROKEN
    assert report.total == 2


def test_assess_attributes_ok():
    attrs = [{"type": "ip-dst", "value": f"1.2.3.{i}"} for i in range(10)]
    assert assess_attributes("tor", attrs, expect=["ip-dst"], min_count=5).status == OK


def test_summary_mentions_status_and_counts():
    text = assess_body("Tor", TOR_LIKE, expect=["ip-dst"]).summary()
    assert text.startswith("OK")
    assert "200 values" in text
