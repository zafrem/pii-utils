# pii-utils

A collection of local command-line tools for finding personally identifiable
information (PII) in real-world data stores. Every tool shares one detection
core — the [pii-pattern-engine](https://github.com/zafrem/pii-pattern-engine)
regex rules plus checksum validators — vendored here as a git submodule so the
tools stay in lockstep with the engine.

Each tool is a standalone CLI binary: no server, no agent, no manager. They run
locally, use your ambient cloud credentials, and write their output to a local
session directory.

## Tools

| Path | What it is |
|------|------------|
| [`grep-cloud-storage/`](grep-cloud-storage) | Scan a **known** AWS S3 bucket/prefix for PII, with same-account checks, cost warnings, rate limiting, and a resumable ledger. |
| [`dark-data-storage/`](dark-data-storage) | **Discover** ungoverned ("dark") S3 buckets in your account — public, unencrypted, untagged — rank them by risk, then sample the flagged ones for PII. |

> **Scope:** only AWS S3 is implemented today. The AWS SDK is the sole cloud
> dependency in both tools; GCS and Azure are not supported.

Also in the repo:

| Path | What it is |
|------|------------|
| [`pii-pattern-engine/`](pii-pattern-engine) | Git submodule: regex rules (multi-region) + Go/Python/Java/JS checksum validators. Shared by every tool. |
| [`privyscope-ner-server/`](privyscope-ner-server) | **Optional** NER sidecar — a small local Python HTTP server wrapping [privyscope](https://github.com/zafrem/privyscope). Not a standalone PII tool; it does nothing on its own and is only used when a tool is run with `--ner`. |

## Detection model

Two complementary layers:

- **Stage 1 — regex + verification** (always on): patterns across US, KR, JP,
  CN, TW, IN, EU, ES, FR and common formats. A match that declares a validator
  (Luhn, IBAN mod-97, KR RRN, …) is gated on that checksum, cutting false
  positives; matches score by severity, boosted when a validator confirms them.
- **Stage 2 — neural NER** (opt-in, `--ner`): privyscope's ONNX BIOES model adds
  contextual entities regex misses (names, addresses). Served by the optional
  sidecar and merged into results, tagged by source. Korean today; en/zh/ja as
  those model packs ship.

## Quick start

```bash
git clone --recurse-submodules <repo-url>
# or, if already cloned:
git submodule update --init --recursive

# Scan a known bucket (regex only)
cd grep-cloud-storage && go build -o grep-cloud-storage . \
  && ./grep-cloud-storage --estimate-only s3://my-bucket/

# Or discover ungoverned buckets and scan the risky ones
cd ../dark-data-storage && go build -o dark-data-storage . \
  && ./dark-data-storage --discover-only
```

To add neural NER (optional), start the sidecar first, then pass `--ner`:

```bash
cd privyscope-ner-server && pip install -r requirements.txt && python server.py &
./grep-cloud-storage/grep-cloud-storage --ner s3://my-bucket/logs/
```

Each tool has its own README with full usage:
[grep-cloud-storage](grep-cloud-storage/README.md) ·
[dark-data-storage](dark-data-storage/README.md) ·
[privyscope-ner-server](privyscope-ner-server/README.md).

## Data handling

Scan results are stored **locally only** — the append-only `results.jsonl`
ledger and `summary.json` are plain file writes; nothing is uploaded, and
findings carry a mask, never the raw matched value. The only outbound traffic is
the cloud read itself (S3 `GET`/`LIST` to pull objects down to scan) and, if you
enable `--ner`, the object text sent to the sidecar — which defaults to
`127.0.0.1` and so stays on the loopback interface unless you point it elsewhere.

## Layout notes

- The engine is a **submodule at the repository root** so every current and
  future tool references the same rule set and validators.
- Each tool's Go module uses a `replace` directive to import the engine's
  `verification` package (`pii_verification`) from the submodule, since it is not
  published under a resolvable import path.
- Language plugins for NER (e.g. `privyscope-ko`) are installed into the sidecar,
  not vendored here.
