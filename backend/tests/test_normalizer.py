from app.ingestion.normalizer import defang_or_clean, detect_indicator_type
from app.models.indicator import IndicatorType


def test_defanging():
    assert defang_or_clean("hxxp://evil[.]com/bad") == "http://evil.com/bad"
    assert defang_or_clean("185[.]220[.]101[.]4") == "185.220.101.4"

def test_type_detection():
    # IP
    t_ip, val_ip = detect_indicator_type("192.168.1.1")
    assert t_ip == IndicatorType.IP
    assert val_ip == "192.168.1.1"

    # SHA-256
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    t_sha, val_sha = detect_indicator_type(sha256.upper())
    assert t_sha == IndicatorType.HASH_SHA256
    assert val_sha == sha256

    # MD5
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    t_md5, val_md5 = detect_indicator_type(md5)
    assert t_md5 == IndicatorType.HASH_MD5
    assert val_md5 == md5

    # CVE
    t_cve, val_cve = detect_indicator_type("cve-2023-34362")
    assert t_cve == IndicatorType.CVE
    assert val_cve == "CVE-2023-34362"

    # Domain
    t_dom, val_dom = detect_indicator_type("malicious-c2-server.org")
    assert t_dom == IndicatorType.DOMAIN
    assert val_dom == "malicious-c2-server.org"

    # URL
    t_url, val_url = detect_indicator_type("hxxp://payloads[.]ru/bin.exe")
    assert t_url == IndicatorType.URL
    assert val_url == "http://payloads.ru/bin.exe"
