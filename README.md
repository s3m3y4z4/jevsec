# JEVSEC

**Project page**: https://s3m3y4z4.github.io/jevsec/ — the tool explained in one screen.

Active decision-support tooling for authorized penetration testing and CTFs, built on local System One-compatible decision engines. Everything runs on your machine; no engagement data leaves it unless you explicitly configure a remote decision backend.

JEVSEC is a **decision and triage layer**: it orders queues and explains every judgment. It never executes commands, never touches your targets, and never replaces your judgment — under the confidence threshold, or on any error, a human reviews.

## Who it is for

Professionals who conduct authorized engagements and know their craft: JEVSEC teaches you the tool, not the discipline. Use it on engagements you are authorized to test, with an operator watching the queues.

## What it does

- **live-triage**: scanner findings in (one JSON object per line), an ordered `TriageRecord` queue out, with `auto`/`review` gates.
- **prioritize**: engagement observations per declared objective (`domain_admin | user_flag | rce_app`, or your own); the model answers only **atomic questions** about the redacted text (credentials? privileges? reachability?) and **the code recombinates** the judgments into a 0–4 impact using the **rubric declared** in `config/prioritization.toml` — reviewable without touching code. The model never sees the objective or scenario words: it judges facts.
- **live-console**: the `jevsecd` daemon keeps real-time engagement sessions — local API, browser console, optional MCP tools for AI agents.

## Quickstart — five minutes, no GPU

Prerequisites: Linux, Python 3.11+ (tested on 3.13), git. No GPU and no model weights needed: the deterministic development backend is enough.

```bash
git clone https://github.com/s3m3y4z4/jevsec && cd jevsec

# deterministic dev backend (no GPU)
python3 harness/mock_systemone.py &
PYTHONPATH=src python3 -m jevsec triage \
  --input data/samples/live_triage_findings.jsonl \
  --config config/live-triage.toml --base-url http://127.0.0.1:8099
```

Expected outcome: one triaged record per input line on stdout, a readable queue on stderr ordered by priority, exit code 0 — the whole run completes in seconds. From clone to last record this path is designed to stay under five minutes on a clean machine.

To use a real engine, see [Real engines on your own hardware](#real-engines-on-your-own-hardware) below — or point `base_url` at any System One-compatible backend you already run. We also publish [**jevsec-002**](https://huggingface.co/dr3x1/jevsec-002), a fine-tuned decision model for security triage (GGUF, Apache-2.0): serve it with any System One-compatible llama.cpp runtime and point `base_url` there.

## The full cycle, with or without an AI agent

The whole workflow works **without any AI agent**, from the command line and from the console:

```bash
PYTHONPATH=src python3 -m jevsec.service --port 7860 &     # daemon: sessions in results/sessions/
PYTHONPATH=src python3 -m jevsec session new --name demo   # open a session
printf '%s\n' '{"id":"o1","text":"Crontab runs /opt/monitor.sh as root; the file is writable by www-data."}' | \
  PYTHONPATH=src python3 -m jevsec session add-observation --session demo --objective user_flag -
PYTHONPATH=src python3 -m jevsec session queue --session demo
PYTHONPATH=src python3 -m jevsec session next --session demo --objective user_flag
```

The browser console (`http://127.0.0.1:7860/`) reads the same queues, shows record details with the redacted observation text, and accepts findings, observations and operator feedback from its forms.

If you drive an AI agent, six optional MCP tools exist (`jevsec_status`, `jevsec_add_finding`, `jevsec_add_observation`, `jevsec_queue`, `jevsec_next`, `jevsec_feedback`):

```bash
claude mcp add jevsec --env PYTHONPATH=$PWD/src -- python3 -m jevsec.mcp_adapter --url http://127.0.0.1:7860
```

During an engagement you will tell your agent "pass this finding to jevsec and show me the queue" or "what does jevsec advise now?": it will use the tools, not memorized commands.

## Assisted execution (off by default)

For every record at the top of a queue, JEVSEC can propose the next operational step as **copyable text** — built by the code from templates you declare in `config/actions.toml` (one per triage bucket, one per winning rule), never by the model.

Optionally, the daemon can also **run** a proposed command — under four hard rules:

1. **Per-action human confirmation**: every single execution asks first; in the CLI it is an interactive prompt, in the console a two-step button. No TTY, no execution.
2. **Templates only, never free text**: the command is rebuilt from the declared template and the record's fields; the client's confirmation can only match the rebuilt command or be refused.
3. **Allowlist and scope**: a tool must be in your `[allowlist]` (empty by default: execution stays disabled) and every target must be inside your declared `[scope]`.
4. **Always audited**: every executed action writes a line to the session's `actions.jsonl` before the daemon answers.

There is **no autonomous execution** and no execution driven by a confidence threshold. See `SECURITY.md`.

## What the model is asked, and what it is not

- **Asked**: a verdict (true_positive / false_positive / needs_review) and pre-authentication reachability, on the redacted finding text only.
- **Not asked**: severity (it comes from the source, e.g. nuclei `info.severity`), hashes, dates, counts: the code does that.
- **Redacted upstream**: hex blobs ≥ 16 chars and base64-like blobs ≥ 24 chars are replaced by placeholders, bodies truncated at `max_state_chars`: the model only sees judgeable text.

## Boundaries (non-negotiable)

- **No execution**: the tool decides and sorts; it launches no commands and sends no traffic to your targets.
- **Local by default**: the only network connection is to the decision backend's `base_url`. A non-loopback backend is opt-in and requires HTTPS plus a token — see the remote backend section.
- **Always gated**: below the confidence threshold, or on any error, the finding goes to human review; nothing is ever silently discarded or auto-approved on error.
- **Auto gate is disabled** (`auto_gate_enabled = false`): the adversarial measurement shipped in this repository's development history showed that injections in response bodies can push the model over threshold. Auto re-arms only after a certified mitigation or recalibration on real data. The tool orders the queue; the human decides. See `SECURITY.md`.
- **Real engagements** always run with an operator watching; the adversarial measurement is replicable with `harness/run_adversarial.py`.

## Structure

- `src/jevsec/` — the tool (CLI, config, redaction, triage, queue, client)
- `config/live-triage.toml` — questions and thresholds, the reviewable control point
- `harness/` — measurement infrastructure: bench runner, deterministic mock, adversarial dataset
- `data/` — synthetic datasets (documentation-reserved values only)
- `ui/console.html` — the browser console

## Tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

Zero dependencies beyond the standard library; development backend: `harness/mock_systemone.py`.

## License

Apache-2.0 — see `LICENSE`. Decision engines and every third-party component downloaded by the `setup/` scripts keep their own licenses; see the engine attribution section.

## Custom objectives, no code changes

`domain_admin | user_flag | rce_app` are three shipped instances of one mechanism, not special cases. Declare your own objective in the rubric TOML — atomic noul questions, rules that the code recombinates into a 0–4 impact, and a default rule:

```toml
[objectives.exfil_path.questions.q_egress]
type = "noul"
instructions = "The observation mentions an outbound channel usable to move data out."

[[objectives.exfil_path.rules]]
name = "exfil_ready"
score = 3
conditions = { q_egress = 0.5, q_reachable = 0.5 }

[objectives.exfil_path.default_rule]
name = "no_signal"
score = 0
```

Semantics: a rule is active when every condition is at or above its threshold; the highest score wins, ties go to the first declared; no active rule means `default_rule`. An incomplete objective (missing questions, rules, or default) is rejected at startup with an error naming the objective and the missing field — no judgment ever runs on an ambiguous rubric. A complete working example lives in `config/examples/custom-objective.toml`; point the daemon at it with `--prioritization-config`.

## Remote decision backend (opt-in)

The default is loopback. If your team runs the engines on another machine, the channel is explicit:

```toml
[backend]
base_url = "https://192.0.2.50:8443"
api_token = "your-token"
```

- A non-loopback `base_url` **requires** `https://` and `api_token`; without both, JEVSEC refuses to start and sends nothing.
- Requests carry `Authorization: Bearer <token>`; certificates are verified against system CAs, always — there is no insecure switch.
- **What travels**: only redacted judgment text. Sessions, feedback, and secrets never leave your machine; the daemon and this console stay bound to loopback in every configuration.
- **TLS termination is your deployment's job** (a reverse proxy or the engine server itself). The console shows a persistent warning while a remote channel is active.
- Before pointing at a third-party hosted engine, read the provider's terms: redacted engagement text would leave your infrastructure.

## Real engines on your own hardware

Measured setup (numbers, not marketing — constitution: measure, don't assume):

| Requirement | Measured value |
|---|---|
| GPU | NVIDIA with ≥ 8 GB VRAM (tested: RTX 4060 Laptop) |
| CUDA / driver | CUDA 12.6 wheel index, driver 550.x |
| Python for the engine venv | 3.12 (`uv`) |
| VRAM behavior | decider-2b fits in 8 GB **only** with reduced CUDA-graph buckets (`DECIDER_T_BUCKETS=256,1024 DECIDER_B_BUCKETS=1,4`, already set by the script); the default grid OOMs on 8 GB |

Install and verify with a real question (never a bare ping):

```bash
bash setup/setup_decider.sh &        # clone + venv + weights; serves loopback :8000
PYTHONPATH=src python3 -m jevsec triage --input data/samples/live_triage_findings.jsonl
```

The triage itself is the health check: every record with a verdict proves the backend answered. The script binds loopback by default; to share the engine across machines see the remote backend section, and put TLS in front before you do.

## Engine attribution

This repository ships **no model weights**: engines are downloaded or served separately. **Our own fine-tuned decision model** — [jevsec-002](https://huggingface.co/dr3x1/jevsec-002), Apache-2.0, a LoRA fine-tune of XHToken/Spark-X2.5-4B (Apache-2.0) trained on human-verified security labels — is published on Hugging Face and is the documented backend. Third-party alternatives, each under its own license — check the upstream pages before redistribution:

- [`Mapika/decider`](https://github.com/Mapika/decider) — decision engine code, Apache-2.0; weights `Mapika/decider-2b` from Hugging Face under the license on the model card.
- [`autotrust/JEV`](https://huggingface.co/autotrust/JEV) — an independent Apache-2.0 open-weights student of the System One class, usable as an alternative backend on machines with larger VRAM (~20 GB for the 9B); same wire schema.

The System One model class and the Jev name belong to TypeSafe AI; JEVSEC is an independent tool and is not affiliated with or endorsed by them.
