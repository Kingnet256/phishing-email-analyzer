# phishing-email-analyzer (`phishcheck`)

An **offline, read-only** phishing indicator scanner for saved `.eml`
files. Point it at a suspicious message and it reports the classic
red flags — without ever fetching a URL, resolving a domain, opening an
attachment, or touching the network. Safe to run on a live sample.

## What it checks

- **Header consistency** — `Reply-To` / `Return-Path` domains vs `From`.
- **Display-name spoofing** — e.g. a name claiming `microsoft.com` from an unrelated domain.
- **Authentication** — parses `Authentication-Results` for SPF / DKIM / DMARC fail/softfail.
- **Deceptive links** — visible text vs real `href`, raw-IP URLs, punycode
  (homograph) hosts, `user@host` tricks, URL shorteners, abused TLDs.
- **Dangerous attachments** — `.exe`, `.hta`, `.iso`, `.htm`, macro-enabled Office, etc.
- **Urgency/lure keywords** in the subject.

Each finding has a severity (`HIGH`/`MEDIUM`/`LOW`/`INFO`). The exit code
equals the number of HIGH findings, so it drops into scripts and pipelines.

## Usage

```bash
python3 src/phishcheck.py samples/phish-sample.eml
python3 src/phishcheck.py suspicious.eml --json     # machine-readable
```

To save a message as `.eml`: in most mail clients, open it and choose
*Save As* / *Export* → `.eml` (or "show original" → save).

## Example

```
$ python3 src/phishcheck.py samples/phish-sample.eml
  [HIGH  ] link_text_mismatch: Link shows 'login.microsoft.com' but points to '192.0.2.10'
  [HIGH  ] risky_attachment: Dangerous attachment type: invoice_scan.exe
  ...
Summary : HIGH=5 MEDIUM=5 LOW=1 INFO=0
```

The bundled samples use `.invalid` / `.example` / documentation-range IP
addresses (RFC 2606 / RFC 5737), so nothing in them is real.

## Design notes / limitations

- **Offline by design.** It reports indicators; it does not "detonate" or
  browse anything. Absence of findings is *not* proof a message is safe.
- Pure Python standard library — no dependencies, Python 3.8+.

## Tests

```bash
python3 -m pytest tests/
```

## License

MIT — see [LICENSE](LICENSE). Analyze only mail you own or are authorized to review.
