"""Genera data/samples/live_triage_findings.jsonl: campione deterministico per il quickstart.

Dieci finding stile nuclei, valori riservati alla documentazione (RFC 5737/2606),
hash generati da sha256 di controvalori. Nessuna casualità: stessa esecuzione,
stesso file. Rigenerare con: python3 setup/make_sample_findings.py
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

OUTPUT_PATH = Path(__file__).parent.parent / "data" / "samples" / "live_triage_findings.jsonl"
LONG_SNIPPET_CHARS = 2500


def fake_hash(counter: int) -> str:
    return hashlib.sha256(f"doc-sample-{counter}".encode()).hexdigest()


def long_snippet() -> str:
    filler = "Server: doc-example/1.0\r\nX-Filler: padding line for truncation test\r\n"
    return (filler * (LONG_SNIPPET_CHARS // len(filler) + 1))[:LONG_SNIPPET_CHARS]


def build_findings() -> list[dict]:
    return [
        {
            "template_id": "doc-example-rce-banner",
            "matched_at": "http://192.0.2.10:8080/",
            "matcher_status": True,
            "response_snippet": "doc-example/1.0 (build 2026.01) vulnerable-banner RCE marker reflected",
            "extracted_results": ["root:/bin/sh match"],
            "info": {"severity": "critical"},
        },
        {
            "template_id": "doc-example-version-mismatch",
            "matched_at": "https://www.example.com/",
            "matcher_status": True,
            "response_snippet": "Apache/2.4.54 (Debian) patched-version banner",
            "info": {"severity": "high"},
        },
        {
            "template_id": "doc-example-xss-reflected",
            "matched_at": "https://www.example.com/search?q=doc",
            "matcher_status": True,
            "response_snippet": "<h1>doc-probe-value</h1> reflected in page body",
            "extracted_results": ["doc-probe-value"],
            "info": {"severity": "medium"},
        },
        {
            "template_id": "doc-example-info-leak",
            "matched_at": "http://192.0.2.22/.well-known/doc.txt",
            "matcher_status": True,
            "response_snippet": "internal note: staging cluster doc.example.internal",
        },
        {
            "template_id": "doc-example-hash-match",
            "matched_at": "http://192.0.2.30/backup.zip",
            "matcher_status": True,
            "response_snippet": f"archive digest {fake_hash(1)} listed in index",
            "extracted_results": [fake_hash(2)],
            "info": {"severity": "low"},
        },
        {
            "template_id": "doc-example-blob-config",
            "matched_at": "http://192.0.2.31/config.b64",
            "matcher_status": True,
            "response_snippet": "Y29uZmlndXJhdGlvbi1ibG9iLWRvY3VtZW50YXppb25hbGUtMjY=",
            "info": {"severity": "medium"},
        },
        {
            "template_id": "doc-example-long-body",
            "matched_at": "http://192.0.2.40/status",
            "matcher_status": True,
            "response_snippet": long_snippet(),
            "info": {"severity": "info"},
        },
        {
            "template_id": "doc-example-no-snippet",
            "matched_at": "http://192.0.2.50/",
            "matcher_status": True,
            "info": {"severity": "low"},
        },
        {
            "template_id": "doc-example-tls-cert",
            "matched_at": "tls://192.0.2.60:443",
            "matcher_status": True,
            "response_snippet": "certificate subject CN=*.example.com expired 2026-01-01",
            "info": {"severity": "low"},
        },
        {
            "template_id": "doc-example-redirect",
            "matched_at": "http://192.0.2.70/old",
            "matcher_status": True,
            "response_snippet": "HTTP/1.1 301 -> https://www.example.com/new open redirect to parameter target",
        },
    ]


def main() -> int:
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", encoding="utf-8") as handle:
        for finding in build_findings():
            handle.write(json.dumps(finding, ensure_ascii=False) + "\n")
    print(f"scritti {len(build_findings())} finding in {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
