#!/usr/bin/env python3
"""
phishcheck — offline phishing indicators for a saved .eml file.

It parses the message with the Python standard library and reports
signals commonly seen in phishing. It is strictly READ-ONLY and OFFLINE:
it never fetches URLs, resolves domains, opens attachments, or talks to
the network. Safe to run on a suspicious sample.

Usage:
    python3 src/phishcheck.py suspicious.eml
    python3 src/phishcheck.py suspicious.eml --json

Exit code = number of HIGH-severity findings (0 = none).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from email import message_from_binary_file, policy
from email.utils import parseaddr
from html.parser import HTMLParser

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at",
}
RISKY_TLDS = {
    "zip", "mov", "xyz", "top", "click", "link", "country", "kim",
    "work", "gq", "tk", "ml", "cf", "ga", "rest", "fit",
}
RISKY_ATTACH = re.compile(
    r"\.(exe|scr|js|jse|vbs|vbe|jar|iso|img|lnk|hta|htm|html|zip|rar|"
    r"7z|docm|xlsm|pptm|ps1|bat|cmd|msi)$",
    re.IGNORECASE,
)
URL_RE = re.compile(r"https?://[^\s\"'<>()]+", re.IGNORECASE)
IP_HOST_RE = re.compile(r"^https?://\d{1,3}(\.\d{1,3}){3}(?:[:/]|$)", re.IGNORECASE)


class LinkExtractor(HTMLParser):
    """Collect (href, visible_text) pairs from HTML anchors."""

    def __init__(self):
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href", "")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def _host(url: str) -> str:
    m = re.match(r"https?://([^/:?#]+)", url, re.IGNORECASE)
    return (m.group(1).lower() if m else "").strip(".")


def _domain(addr: str) -> str:
    return addr.split("@")[-1].lower().strip(">") if "@" in addr else ""


def add(findings, severity, code, detail):
    findings.append({"severity": severity, "code": code, "detail": detail})


def analyze(path: str) -> dict:
    with open(path, "rb") as fh:
        msg = message_from_binary_file(fh, policy=policy.default)

    findings: list[dict] = []

    from_name, from_addr = parseaddr(msg.get("From", ""))
    _, reply_addr = parseaddr(msg.get("Reply-To", ""))
    _, return_addr = parseaddr(msg.get("Return-Path", ""))
    from_dom = _domain(from_addr)

    # --- Header consistency ---
    if reply_addr and _domain(reply_addr) and _domain(reply_addr) != from_dom:
        add(findings, "HIGH", "reply_to_mismatch",
            f"Reply-To domain ({_domain(reply_addr)}) != From domain ({from_dom})")
    if return_addr and _domain(return_addr) and _domain(return_addr) != from_dom:
        add(findings, "MEDIUM", "return_path_mismatch",
            f"Return-Path domain ({_domain(return_addr)}) != From domain ({from_dom})")

    # Display name that impersonates a domain different from the real one
    dn_dom = re.search(r"([a-z0-9.-]+\.[a-z]{2,})", from_name.lower())
    if dn_dom and from_dom and dn_dom.group(1) not in from_dom:
        add(findings, "MEDIUM", "display_name_spoof",
            f"Display name mentions '{dn_dom.group(1)}' but sender is '{from_dom}'")

    # --- Authentication results ---
    auth = " ".join(msg.get_all("Authentication-Results", [])).lower()
    for mech in ("spf", "dkim", "dmarc"):
        if f"{mech}=fail" in auth or f"{mech}=softfail" in auth:
            sev = "HIGH" if mech == "dmarc" else "MEDIUM"
            add(findings, sev, f"{mech}_fail", f"{mech.upper()} did not pass")
    if not auth:
        add(findings, "INFO", "no_auth_results",
            "No Authentication-Results header (can't confirm SPF/DKIM/DMARC)")

    # --- Body: gather text + html ---
    text_body, html_body = "", ""
    for part in msg.walk():
        ctype = part.get_content_type()
        if part.is_multipart():
            continue
        disp = str(part.get("Content-Disposition", ""))
        if "attachment" in disp.lower():
            fname = part.get_filename() or "(unnamed)"
            if RISKY_ATTACH.search(fname):
                add(findings, "HIGH", "risky_attachment",
                    f"Dangerous attachment type: {fname}")
            else:
                add(findings, "INFO", "attachment", f"Attachment: {fname}")
            continue
        try:
            payload = part.get_content()
        except Exception:
            continue
        if ctype == "text/plain":
            text_body += payload if isinstance(payload, str) else ""
        elif ctype == "text/html":
            html_body += payload if isinstance(payload, str) else ""

    # --- URLs ---
    urls = set(URL_RE.findall(text_body))
    if html_body:
        p = LinkExtractor()
        try:
            p.feed(html_body)
        except Exception:
            pass
        for href, text in p.links:
            if href.lower().startswith(("http://", "https://")):
                urls.add(href)
                vis = URL_RE.search(text or "")
                if vis and _host(vis.group(0)) and _host(vis.group(0)) != _host(href):
                    add(findings, "HIGH", "link_text_mismatch",
                        f"Link shows '{_host(vis.group(0))}' but points to '{_host(href)}'")

    for url in sorted(urls):
        host = _host(url)
        if IP_HOST_RE.match(url):
            add(findings, "HIGH", "ip_literal_url", f"URL uses a raw IP address: {url}")
        if "xn--" in host:
            add(findings, "HIGH", "punycode_url", f"Punycode (possible homograph) host: {host}")
        if host in SHORTENERS:
            add(findings, "MEDIUM", "url_shortener", f"URL shortener hides destination: {host}")
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in RISKY_TLDS:
            add(findings, "LOW", "risky_tld", f"Uncommon/abused TLD .{tld}: {host}")
        if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
            add(findings, "HIGH", "userinfo_url", f"URL embeds credentials/@ trick: {url}")

    # --- Subject urgency cues ---
    subject = str(msg.get("Subject", ""))
    if re.search(r"\b(urgent|immediately|verify|suspend|locked|24 hours|"
                 r"account|password|invoice|payment)\b", subject, re.IGNORECASE):
        add(findings, "LOW", "urgency_subject", f"Urgency/lure keywords in subject: {subject!r}")

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in ("HIGH", "MEDIUM", "LOW", "INFO")}
    return {
        "file": path,
        "from": from_addr, "subject": subject,
        "urls": sorted(urls),
        "findings": findings, "counts": counts,
    }


def render(report: dict) -> str:
    lines = [f"File    : {report['file']}",
             f"From    : {report['from']}",
             f"Subject : {report['subject']}",
             f"URLs    : {len(report['urls'])}", ""]
    if not report["findings"]:
        lines.append("No phishing indicators found (absence of signal is not proof of safety).")
    else:
        lines.append("Findings:")
        for f in report["findings"]:
            lines.append(f"  [{f['severity']:6}] {f['code']}: {f['detail']}")
    c = report["counts"]
    lines += ["", f"Summary : HIGH={c['HIGH']} MEDIUM={c['MEDIUM']} "
              f"LOW={c['LOW']} INFO={c['INFO']}"]
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("eml", help="path to a saved .eml file")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = ap.parse_args(argv)
    try:
        report = analyze(args.eml)
    except FileNotFoundError:
        print(f"error: no such file: {args.eml}", file=sys.stderr)
        return 255
    print(json.dumps(report, indent=2) if args.json else render(report))
    return report["counts"]["HIGH"]


if __name__ == "__main__":
    raise SystemExit(main())
