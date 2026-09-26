# Changelog

Notable, user-visible changes per version. Dates are ISO-8601.

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
