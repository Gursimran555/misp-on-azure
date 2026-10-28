import pytest

from mispkit.indicators import defang, detect_type, lint_indicator, lint_indicators, refang


@pytest.mark.parametrize("value,expected", [
    ("8.8.8.8", "ip"),
    ("2001:4860:4860::8888", "ip"),
    ("d41d8cd98f00b204e9800998ecf8427e", "md5"),
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"),
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"),
    ("https://evil.example.com/login", "url"),
    ("hxxps://evil[.]example[.]com/login", "url"),
    ("evil-domain.com", "domain"),
    ("sub.evil-domain.co.uk", "domain"),
    ("invoice.pdf", "filename"),
    ("payload.exe", "filename"),
    ("bad@evil-domain.com", "email"),
    ("not an indicator", "unknown"),
])
def test_detect_type(value, expected):
    assert detect_type(value) == expected


def test_refang_and_defang_roundtrip():
    assert refang("hxxps://www[.]arizona99[.]co/") == "https://www.arizona99.co/"
    assert refang("1(.)2(.)3(.)4") == "1.2.3.4"
    assert refang("user[@]evil[.]com") == "user@evil.com"
    assert defang("https://evil.com") == "hxxps://evil[.]com"
    assert refang(defang("https://evil.com/a.b")) == "https://evil.com/a.b"


def levels(findings):
    return [f.level for f in findings]


def test_empty_file_md5_is_an_error():
    findings = lint_indicator("d41d8cd98f00b204e9800998ecf8427e", "md5")
    assert "error" in levels(findings)
    assert "empty file" in findings[0].message


def test_empty_file_sha256_is_an_error_even_uppercase():
    value = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    assert "error" in levels(lint_indicator(value, "sha256"))


def test_real_looking_hash_is_clean():
    assert lint_indicator("33cb0ec1eccfb398abebdc04106729f1", "md5") == []


def test_wrong_hash_length():
    findings = lint_indicator("33cb0ec1eccfb398abebdc04106729f1aa", "md5")
    assert "error" in levels(findings)


def test_type_mismatch():
    findings = lint_indicator("evil-domain.com", "ip-dst")
    assert any("looks like domain" in f.message for f in findings)


def test_documentation_ip_is_a_warning():
    findings = lint_indicator("203.0.113.25", "ip-src")
    assert levels(findings) == ["warning"]
    assert "documentation" in findings[0].message


def test_private_ip_is_a_warning():
    findings = lint_indicator("10.0.0.5", "ip-dst")
    assert levels(findings) == ["warning"]
    assert "private" in findings[0].message


def test_public_ip_is_clean():
    assert lint_indicator("1.161.151.139", "ip-dst") == []


def test_reserved_tld_warning_for_domain_url_and_email():
    assert "warning" in levels(lint_indicator("secure-login-example.test", "domain"))
    assert "warning" in levels(lint_indicator("https://a.example/x", "url"))
    assert "warning" in levels(lint_indicator("a@b.invalid", "email-src"))


def test_defanged_value_gets_info_note():
    findings = lint_indicator("evil-domain[.]com", "domain")
    assert levels(findings) == ["info"]


def test_text_attributes_are_not_type_checked():
    assert lint_indicator("Phishing email delivered to finance users.", "text") == []


def test_duplicates_are_reported_after_refang():
    items = [{"value": "evil-domain.com", "type": "domain"},
             {"value": "evil-domain[.]com", "type": "domain"}]
    assert any("appears 2 times" in f.message for f in lint_indicators(items))


def test_empty_value():
    assert levels(lint_indicator("   ")) == ["error"]
