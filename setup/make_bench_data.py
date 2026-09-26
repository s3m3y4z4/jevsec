"""Genera i dataset di benchmark per i 4 task. Deterministico (seme fisso).

Tutti i valori sono sintetici e riservati alla documentazione:
IP in 192.0.2.0/24 e 2001:db8::/32 (RFC 5737/3849), domini example.* (RFC 2606),
hash generati da controvalori, CVE inventati o didattici.
"""

from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path
from typing import Any

RNG = random.Random(20260922)
DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "bench"


def host_ip() -> str:
    return f"192.0.2.{RNG.randint(2, 250)}"


def host_v6() -> str:
    return f"2001:db8::{RNG.randint(2, 9999):x}"


def domain() -> str:
    return RNG.choice(["app.example.com", "shop.example.org", "api.example.net", "portal.example.com", "intranet.example.org"])


def fake_hash(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def write_jsonl(name: str, cases: list[dict[str, Any]]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = DATA_DIR / f"{name}.jsonl"
    with path.open("w", encoding="utf-8") as handle:
        for case in cases:
            handle.write(json.dumps(case, ensure_ascii=False) + "\n")
    print(f"{path}: {len(cases)} casi")


def scanner_triage() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []

    def add(verdict: str, severity: int, no_auth: int, state: dict[str, Any]) -> None:
        cases.append({"id": f"sb-{len(cases) + 1:03d}", "state": state, "labels": {"verdict": verdict, "severity": severity, "no_auth": no_auth}})

    true_positives = [
        ("apache-path-traversal", 4, "root:x:0:0:root:/root:/bin/bash", ["lfi"]),
        ("shellshock-rce", 4, "uid=33(www-data) gid=33(www-data)", ["rce"]),
        ("git-config-exposure", 3, "[core] repositoryformatversion = 0", ["exposure"]),
        ("default-login", 3, "login successful for admin:admin", ["auth"]),
        ("backup-file-exposure", 3, "MySQL dump -- Host: localhost", ["exposure"]),
        ("api-key-leak", 3, "x-api-key: " + fake_hash("apikey")[:32], ["secret"]),
        ("openssl-heartbleed", 3, "leaked 64 bytes: .....peek", ["cve"]),
        ("sqli-error-based", 2, "SQLSTATE[42000]: Syntax error or access violation: 1064", ["sqli"]),
        ("reflected-xss-param", 2, "<p>Results for: <script>alert(1)</script></p>", ["xss"]),
        ("cors-misconfig-credentials", 2, "Access-Control-Allow-Origin: https://evil.example.net + credentials true", ["cors"]),
        ("smtp-open-relay", 2, "250 2.0.0 Ok: queued as " + fake_hash("smtp")[:12].upper(), ["mail"]),
        ("smb-null-session", 2, "Share list: IPC$ SYSVOL NETLOGON backup", ["smb"]),
        ("wordpress-xmlrpc-enabled", 1, "system.multicall methods available", ["cms"]),
        ("open-redirect-param", 1, "Location: https://evil.example.net/landing", ["redirect"]),
        ("verbose-stack-trace", 1, "Traceback (most recent call last): File \"/app/handlers.py\"", ["info"]),
        ("service-version-banner", 0, "220 ftp.example.net FTP server (vsftpd 3.0.3)", ["tech"]),
    ]
    for template, severity, proof, tags in true_positives:
        add("true_positive", severity, 1, {
            "tool": "nuclei", "template_id": template, "matched_at": f"https://{domain()}/" if severity < 4 else f"http://{host_ip()}/",
            "matcher_status": True, "extracted_results": [proof], "tags": tags,
        })

    false_positives = [
        ("apache-rce-cve-2021-42013", 4, f"Apache/2.4.{RNG.randint(55, 58)} (Debian)"),
        ("shellshock-rce", 4, "CGI script returns static help text, no environment output"),
        ("struts-ognl-rce", 4, "404 on /struts.action endpoints, Struts not deployed"),
        ("openssl-heartbleed", 3, "OpenSSL/3.0.{RNG.randint(2, 9)} in handshake banner"),
        ("backup-file-exposure", 3, "backup-*.tar.gz listed but download returns 401 with valid creds required"),
        ("sqli-error-based", 2, "payload encoded server-side: q=%3Cscript%3E echoed as plain text, not executed"),
        ("reflected-xss-param", 2, "response contains &lt;script&gt; escaped, no execution context"),
        ("git-config-exposure", 3, "/.git/ returns 403 Forbidden on all probes"),
    ]
    for template, severity, evidence in false_positives:
        add("false_positive", severity, 1, {
            "tool": "nuclei", "template_id": template, "matched_at": f"https://{domain()}/",
            "matcher_status": True, "extracted_results": [], "response_snippet": evidence, "tags": ["cve"],
        })

    needs_review = [
        ("generic-debug-endpoint", 3, "HTTP 502 Bad Gateway"),
        ("openssl-heartbleed", 3, "connection reset during heartbeat test"),
        ("api-rate-limit-bypass", 2, "HTTP 429 Too Many Requests on verification request"),
        ("admin-panel-exposure", 2, "HTTP 401 with WWW-Authenticate: Basic on /admin, no creds tested"),
        ("cve-2026-1337-client-side", 2, "matcher fired on header echo, client-side impact unclear"),
        ("sqli-time-based", 2, "response time variance within noise range (no baseline recorded)"),
        ("auth-bypass-path", 3, "404 on recheck: endpoint removed between scan and verification"),
        ("tls-deprecated-protocol", 1, "TLS handshake failure on follow-up connection"),
    ]
    for template, severity, evidence in needs_review:
        add("needs_review", severity, 1, {
            "tool": "nuclei", "template_id": template, "matched_at": f"https://{domain()}/",
            "matcher_status": True, "extracted_results": [], "response_snippet": evidence, "tags": ["review"],
        })

    RNG.shuffle(cases)
    return cases


def ctf_routing() -> list[dict[str, Any]]:
    challenges = [
        ("sqli", "The product search at https://{d}/search breaks with a SQL error when I add a quote. The flag is in the products table.", 1, 0),
        ("sqli", "Login is just a query. Try admin'-- and read the flag from the users table at https://{d}/login.", 1, 0),
        ("sqli", "Sorting products with ?order= changes the query. Blind: the page loads slower with sleep(5). Flag at https://{d}/shop.", 1, 0),
        ("xss", "The feedback form at https://{d}/feedback renders your message back. A bot with admin cookies visits every minute.", 1, 0),
        ("xss", "The profile page shows your display name to anyone who visits. Steal the admin session from https://{d}/u/admin.", 1, 0),
        ("ssti", "Flask code: return render_template_string('<h1>Hi ' + name + '</h1>'). Get the flag at https://{d}/.", 1, 0),
        ("ssti", "Our newsletter greets you by name through a Twig template: Hello {{ name }}. https://{d}/news.", 1, 0),
        ("jwt_flaw", "Grab your token at https://{d}/login then call /flag as admin. Header says alg HS256; the secret is short.", 1, 0),
        ("jwt_flaw", "We accept any algorithm the token declares. Become admin at https://{d}/api and read the flag.", 1, 0),
        ("path_traversal", "The download link ?file=report.pdf reads from disk. Read /etc/passwd then the flag file at https://{d}/dl.", 1, 0),
        ("path_traversal", "The image proxy at https://{d}/img?url=cat.png can fetch more than images. Fetch the flag from the local file.", 1, 0),
        ("deserialization", "The session cookie is a base64 pickle. The server unpickles it. Get code execution and read the flag at https://{d}/.", 1, 0),
        ("deserialization", "The import feature accepts a serialized Java object. Craft one and read /flag at https://{d}/import.", 1, 0),
        ("broken_auth", "The login checks the password client-side and hides the admin flag endpoint. https://{d}/login.", 1, 0),
        ("broken_auth", "Password reset uses the username as token part. Reset the admin account at https://{d}/reset.", 1, 0),
        ("crypto_classic", "E hvvh qh qhwzrun. Wkh iodj orrhv olnh wklv: SYNT{example}. Each letter moved the same way.", 0, 0),
        ("crypto_classic", "The attached cipher repeats a 5-letter key. Frequency analysis will do. Plaintext ends with the flag.", 0, 1),
        ("encoding", "The flag went through base64, then rot13, then hex. Peel the layers.", 0, 0),
        ("encoding", "A QR code made only of characters, decoded from the attached text file.", 0, 1),
        ("reverse_engineering", "The attached binary asks for a license key and prints the flag for the right one. Everything runs locally.", 0, 1),
        ("reverse_engineering", "A custom VM executes the attached bytecode; the validator hides the flag inside. Recover the accepted input.", 0, 1),
        ("pwn_binary", "nc {h} 1337. The attached binary reads 64 bytes into a 32-byte buffer. Get a shell and cat the flag.", 1, 1),
        ("pwn_binary", "nc {h} 9911. format string in the logger; win() is never called but exists in the attached ELF.", 1, 1),
        ("forensics", "The attached memory dump belongs to a workstation that exfiltrated the flag. Find it.", 0, 1),
        ("forensics", "Reassemble the file transferred in the attached FTP capture between two hosts.", 0, 1),
        ("forensics", "The web server log in the attachment contains one request that is not like the others. Extract the flag.", 0, 1),
        ("stego", "The attached PNG has something appended after IEND.", 0, 1),
        ("stego", "Listen carefully to the attached WAV: the flag is spoken in a band you cannot hear.", 0, 1),
        ("stego", "Two attached images look identical. XOR them.", 0, 1),
        ("logic_flaw", "The shop at https://{d}/ sells the flag for 100 coins but negative quantities are accepted at checkout.", 1, 0),
        ("logic_flaw", "The coupon at https://{d}/ can be redeemed twice if two tabs confirm at the same moment.", 1, 0),
        ("other", "The flag is written in the challenge title. No hacking required, just read it.", 0, 0),
        ("other", "Call the phone number in the attached business card and listen to the voicemail.", 0, 1),
    ]
    cases: list[dict[str, Any]] = []
    for index, (attack_class, template, has_server, has_files) in enumerate(challenges):
        description = template.replace("{d}", domain()).replace("{h}", host_ip())
        attachments = ["artifact.bin", "capture.pcap", "dump.raw", "challenge.elf", "notes.txt", "image.png", "audio.wav"][: RNG.randint(1, 2)] if has_files else []
        cases.append({
            "id": f"cb-{index + 1:03d}",
            "state": {"title": f"Challenge {index + 1}", "category_hint": "unknown", "description": description, "attachments": attachments},
            "labels": {"attack_class": attack_class, "has_server": has_server, "has_files": has_files},
        })
    RNG.shuffle(cases)
    return cases


def report_claim() -> list[dict[str, Any]]:
    pairs = [
        ("GET /admin returned 200 with the dashboard, no credentials sent.", "The admin panel is accessible without authentication.", 1, 0),
        ("Anonymous FTP on the host allowed listing and reading /shared/credentials_old.txt with username:password pairs.", "Anonymous FTP exposes a file containing usernames and passwords.", 1, 0),
        ("Command injection via the ip parameter returned 'uid=33(www-data)' in the HTTP response.", "Command execution appears possible through the ip parameter.", 1, 0),
        ("The TLS certificate expired 3 months ago; no other anomaly in the handshake.", "The service presents an expired TLS certificate.", 1, 0),
        ("Response headers include Server: nginx/1.18.0 and X-Powered-By: PHP/7.4.33.", "The web server discloses software versions in response headers.", 1, 0),
        ("POST /login with admin:admin returned 302 to /admin and a session for role administrator.", "Default credentials grant administrative access.", 1, 0),
        ("The backup archive was listed by the web server but its download required valid credentials (401).", "A critical remote code execution via the exposed backup archive allows full server takeover.", 0, 1),
        ("The search parameter reflects input in the same response only; nothing is stored or shown to other users.", "A stored cross-site scripting vulnerability lets the attacker hijack any user session application-wide.", 0, 1),
        ("The TLS scan found an expired certificate with strong ciphers otherwise negotiated.", "Remote command execution is possible through the expired TLS certificate.", 0, 1),
        ("A directory listing exposed one backup archive that requires authentication to download.", "All server backups are publicly downloadable without authentication.", 0, 1),
        ("One reflected XSS was confirmed in the search parameter of app.example.com.", "A cross-site scripting vulnerability affects every parameter of the application.", 0, 1),
        ("Verbose error pages disclose stack traces with local file paths.", "Path traversal allows reading arbitrary files from the server filesystem.", 0, 1),
        ("An outdated jQuery 1.12 library is included by the main page.", "A known critical vulnerability in the page dependencies enables remote code execution.", 0, 1),
        ("The login form lacks rate limiting; 500 attempts were accepted without lockout.", "The authentication mechanism can be bypassed entirely by brute force.", 0, 1),
        ("GET /.git/config returned 403 Forbidden on every probe.", "The Git repository of the application is exposed and downloadable.", 0, 1),
        ("Session cookies lack the HttpOnly flag.", "Session tokens can be stolen remotely by any attacker without user interaction.", 0, 1),
        ("The application allows upload of .png files up to 2 MB.", "Unrestricted file upload allows deploying a web shell and executing code.", 0, 1),
        ("An expired certificate was observed on the mail relay host.", "The expired certificate on the TLS endpoint enables command execution.", 0, 1),
        ("DNS zone transfer was refused by the primary name server (REFUSED).", "The name server leaks the full internal zone to any client.", 0, 1),
        ("The /api/v1 endpoints require a valid token; enumeration found no unauthenticated route.", "The entire API is accessible without authentication.", 0, 1),
    ]
    cases: list[dict[str, Any]] = []
    for index, (evidence, claim, supported, exaggerates) in enumerate(pairs):
        cases.append({
            "id": f"rb-{index + 1:03d}",
            "state": {"evidence": evidence, "claim": claim},
            "labels": {"supported": supported, "backed": 1 - exaggerates},
        })
    RNG.shuffle(cases)
    return cases


def prioritization() -> list[dict[str, Any]]:
    domain_objective = "Compromise the corporate domain (obtain Domain Admin) from a workstation inside the network."
    host_objective = "Obtain the user flag in the home directory of user 'target' on the internal workstation."
    web_objective = "Achieve remote code execution on the web application at app.example.com."
    observations = [
        (domain_objective, "SYSVOL contains a Group Policy with a cpassword attribute for the local-admin account.", 4, 1),
        (domain_objective, "Kerberoasting found SPN account svc-backup with 'Password never expires' and predictable naming.", 3, 1),
        (domain_objective, "AS-REP roasting found user intern1 with pre-authentication disabled.", 2, 1),
        (domain_objective, "Unquoted service path with writable application directory on the local host.", 2, 1),
        (domain_objective, "A domain user's spreadsheet on a share lists the wifi password of the HQ office.", 1, 1),
        (domain_objective, "Old Joomla with public RCE found on an isolated lab VLAN with no route to the domain.", 0, 1),
        (domain_objective, "A network printer discloses firmware version 2.0.1 on its web interface.", 0, 1),
        (domain_objective, "Constrained delegation is enabled for the app-server account; no known abuse path matches the environment.", 3, 0),
        (domain_objective, "NTLM relay candidates exist but all targets enforce signing.", 1, 0),
        (host_objective, "Winlogon autologon entries on a compromised peer workstation store the password of 'target'.", 4, 1),
        (host_objective, "Unquoted service path 'Updater' with write access to its binary directory on the same host.", 3, 1),
        (host_objective, "AlwaysInstallElevated is enabled on the target host and the current user can run msiexec.", 4, 1),
        (host_objective, "The target has an SMB share 'public' readable by everyone, containing only marketing PDFs.", 1, 1),
        (host_objective, "A sticky-notes database file on a different host belongs to another user.", 1, 0),
        (host_objective, "The target's AV agent version is disclosed in the windows events; no bypass is known for it.", 0, 1),
        (host_objective, "Credentials for a local account of an unrelated retired server are stored in a saved RDP file.", 0, 1),
        (host_objective, "Scheduled task runs as 'target' executing a script from a directory the current user can write.", 4, 0),
        (web_objective, "The /upload endpoint accepts .svg files that are served inline from the same origin.", 3, 1),
        (web_objective, "The id parameter returns a database error when a quote is appended.", 4, 1),
        (web_objective, "An old admin interface is exposed at /legacy with HTTP basic auth prompting.", 2, 0),
        (web_objective, "Directory fuzzing found /.git/ returning 403 on all paths.", 2, 0),
        (web_objective, "The application discloses the framework version in a 500 error page.", 1, 1),
        (web_objective, "The API documents a deprecated /v0/export endpoint not present in current routes.", 1, 0),
        (web_objective, "Reflected XSS in the search parameter executes in the attacker's own browser only.", 1, 1),
        (web_objective, "A password reset token is returned in the response body of the requesting user.", 3, 1),
    ]
    cases: list[dict[str, Any]] = []
    for index, (objective, observation, impact, quick_win) in enumerate(observations):
        cases.append({
            "id": f"pb-{index + 1:03d}",
            "state": {"objective": objective, "observation": observation},
            "labels": {"impact": impact, "quick_win": quick_win},
        })
    RNG.shuffle(cases)
    return cases


def main() -> None:
    write_jsonl("scanner_triage", scanner_triage())
    write_jsonl("ctf_routing", ctf_routing())
    write_jsonl("report_claim", report_claim())
    write_jsonl("prioritization", prioritization())


if __name__ == "__main__":
    main()
