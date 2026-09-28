import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import phishcheck  # noqa: E402

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")


def codes(path):
    return {f["code"] for f in phishcheck.analyze(path)["findings"]}


def test_phish_flags_the_big_signals():
    c = codes(os.path.join(SAMPLES, "phish-sample.eml"))
    for expected in ("reply_to_mismatch", "dmarc_fail", "spf_fail",
                     "link_text_mismatch", "ip_literal_url",
                     "url_shortener", "risky_attachment", "urgency_subject"):
        assert expected in c, f"missing {expected}"


def test_clean_has_no_high_findings():
    rep = phishcheck.analyze(os.path.join(SAMPLES, "clean-sample.eml"))
    assert rep["counts"]["HIGH"] == 0


def test_host_and_domain_helpers():
    assert phishcheck._host("https://Sub.Example.com/x") == "sub.example.com"
    assert phishcheck._domain("a@b.com") == "b.com"
