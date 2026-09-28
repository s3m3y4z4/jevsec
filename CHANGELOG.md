# Changelog

Notable, user-visible changes per version. Dates are ISO-8601.

## 0.4-beta.1 — session inbox: deliver files instead of pasting

*Pre-release: published as `v0.4-beta.1` for early use; the stable line stays 0.3 until this is validated in the field.*

- **Session inbox (drop-zone)**: copy `findings-*.jsonl` or `observations-<objective>-*.jsonl` into `results/sessions/<session>/inbox/` and the daemon evaluates every line within `[inbox] interval_s` (default 2 s). Delivered files are archived, never deleted; the feature turns off with `[inbox] enabled = false`.
- **Delivery log per session** (`inbox-log.jsonl`, the "Inbox deliveries" console panel, and the new `jevsec_inbox` MCP tool): every file closes with a final status — processed, partial, rejected, already-processed or interrupted — with per-line outcomes, per-line errors and durations.
- **Crash-safe by construction**: deliveries are addressed by the sha256 of their content (recopying the same file evaluates nothing twice); a daemon restart closes interrupted deliveries without ever re-evaluating them, and records already written stay exactly once.
- **Duplicate findings are skipped, not re-judged**: triage records now persist `finding_hash` (computed on the raw finding before redaction); a delivered line whose exact content is already in the queue counts as a duplicate in the log, whatever channel it arrived from.
- **The inbox only evaluates**: no delivered file can trigger an action or any traffic beyond the configured backend.

## 0.3 — triage feedback loop, host_admin rubric, questions under observation

- **Operator feedback on triage records**: `jevsec_feedback` now accepts finding refs — record the verdict you consider correct (`verdict_atteso`) and the pre-auth answer (`no_auth_atteso`). The CLI gains `--verdict`, `--no-auth` and `--giudizi`; the console adds a feedback form to every finding card. Verdicts on triage feed the training-data loop — feedback only: triage rows without an operator verdict never enter the dataset.
- **New built-in rubric `host_admin`** (highest-privilege account on a host): `path_as_root` 4, `privileged_material` 3, `escalation_to_admin` 2, `credentials` 1 — assembled from existing atomic questions, no new ones, reviewable in `config/prioritization.toml`.
- **Six questions under observation** (`is_proof_value`, `is_riddle_or_challenge`, `source_is_first_party`, `credential_verified`, `is_central_service`, `is_deceptive_measure`): declared on the relevant objectives but referenced by no rule. They produce informative judgments and collect labeled data from real sessions; promotion to rules happens only when the data exists.
- **Bench rows only for rule questions**: questions that no rule references never receive invented labels from synthetic benches.
- **Console**: inline favicon (no extra route or asset); feedback form on finding cards.
- **Config**: `model` materialized in `config/live-triage.toml`.
- **Docs**: new "Serving your own engine" section; engine wording fixed (the install script sets up decider-2b; jevsec-003 is the backend we run and publish); the custom-objective example now declares every question its rules reference.

## 0.2 — assisted execution, engine-agnostic channel

- **Suggested playbooks**: every top record carries the next operational step as copyable text, built by the code from templates in `config/actions.toml` (never by the model); an inert, fully documented example ships in `config/examples/actions.toml`.
- **Assisted execution (off by default)**: the daemon can run a proposed command only under four hard rules — per-action human confirmation (interactive prompt / two-step button; no TTY, no execution), template-only commands (the client's confirmation must match the rebuilt command or it is refused), allowlisted tools and declared target scope, and a per-action audit log (`actions.jsonl`) written before the daemon answers. No autonomous execution exists.
- **CLI**: `jevsec session run` (shows the exact command, asks confirmation) and `jevsec session actions` (audit log).
- **Channel**: requests to the decision backend now carry the `model` field (`[backend] model`, default `jev-latest`), as in the original System One wire contract.
- **Documentation**: the `reflex` engine and its setup script are gone; the installable open engine is decider-2b, and any System One-compatible backend can be used via `base_url`.
- **Constitution-level guarantee unchanged**: the auto gate stays disabled; no threshold drives any action.

## 0.1 — first public release

Initial public release of the decision-support tooling for authorized security testing.

- **live-triage**: scanner findings in, ordered `TriageRecord` queue out, with `auto`/`review` gates; adversarial measurement that keeps the auto gate disabled ships in the repository history, `harness/run_adversarial.py` reproduces the methodology.
- **prioritize**: engagement observations per declared objective; the model answers atomic questions on redacted text only, the code recombinates judgments into 0–4 impact with the rubric declared in TOML.
- **live-console**: `jevsecd` daemon with local API, browser console (ingest forms, record details with redacted observation text, operator feedback), and six optional MCP tools for AI agents.
- **No AI agent required**: the full cycle runs from the CLI (`jevsec session …`) and from the console forms, with identical effects.
- **Custom objectives**: declare your own objectives and rubrics in TOML, no code changes; incomplete rubrics are rejected at startup with a precise error.
- **Remote decision backend (opt-in)**: non-loopback backends require HTTPS and a bearer token or the tool refuses to start; only redacted judgment text travels; the daemon and console always stay on loopback.
- **Zero dependencies** beyond the Python standard library; deterministic development backend included for GPU-less machines.
- Single version source: `jevsec.__version__`, `--version`.
