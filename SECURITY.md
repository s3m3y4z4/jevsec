# Security Policy

## What this software is

JEVSEC is a decision-support layer for authorized security testing. It sorts queues and explains its judgments; it never executes commands and never sends traffic to your targets. It is not a scanner, not an exploitation framework, and not a substitute for operator judgment.

## Threat model

The core input is **hostile by construction**: finding bodies and observation text can contain anything an attacker put in a response — banners, payloads, injected instructions. JEVSEC treats every byte of target-controlled text as untrusted input:

- **Redaction before judgment**: hex blobs ≥ 16 characters and base64-like blobs ≥ 24 characters are replaced by placeholders before any model sees the text; bodies are truncated at a configured limit. The model judges words, not artifacts.
- **The model never acts**: its output is a probability on an atomic question. Recombination into impact scores, gates and queue order happens in code. Nothing is executed as a consequence of a judgment.
- **The operator is always in the loop**: below the confidence threshold, or on any error, records go to human review. Records are never silently discarded, and errors never auto-approve.

## Known limitation: prompt injection moves the model (auto gate disabled)

The vendor of the underlying model class documents that adversarial content in the state can move its answers (injection in response bodies is a documented failure mode). Our own adversarial measurement confirmed it on this pipeline: crafted finding bodies can push the verdict probability over the auto-approval threshold.

Consequence, shipped in the default configuration:

- `auto_gate_enabled = false` — the tool **orders** the queue and gates records for review; it never auto-approves. The auto gate re-arms only after a certified mitigation or recalibration on real engagement data.
- The adversarial measurement is replicable: `harness/run_adversarial.py` rebuilds the paired-benchmark methodology used to reach this decision.

Treat every `auto` bucket you may enable yourself as a claim you have tested against your own data.

## Data boundaries

- **Local by default**: the only outbound connection is to the decision backend's `base_url` (default loopback). No telemetry, no update checks, no third-party calls.
- **Remote backend is opt-in**: any non-loopback `base_url` must use HTTPS and a bearer token, or the tool refuses to start. Only redacted text is ever sent to the backend; sessions, feedback and secrets never leave the machine. Terminating TLS is the deployment's responsibility.
- **Engagement records stay on disk**, under your sessions directory: treat that directory as engagement data.

## Reporting a vulnerability

Open a private security advisory on the repository (or a regular issue if your report contains nothing that should stay private). Please do not include real engagement data, client names, or live indicators in your report: synthetic examples only.

## Scope of this policy

This policy covers JEVSEC's own code. The decision engines you download with the `setup/` scripts, their weights and their serving stacks carry their own upstream security posture and licenses.
