# pii-utils

A collection of tools for finding personally identifiable information (PII) in
real-world data stores. Every tool shares one detection core — the
[pii-pattern-engine](https://github.com/zafrem/pii-pattern-engine) regex rules
plus checksum validators — vendored here as a git submodule so the tools stay in
lockstep with the engine.

## Contents

| Path | What it is |
|------|------------|
| [`pii-pattern-engine/`](pii-pattern-engine) | Git submodule: 204 regex rules (multi-region) + Go/Python/Java/JS checksum validators. Shared by every tool. |
| [`grep-cloud-storage/`](grep-cloud-storage) | Go CLI that scans objects in S3, GCS, or Azure Blob Storage for PII. |
| [`privyscope-ner-server/`](privyscope-ner-server) | Python HTTP sidecar wrapping [privyscope](https://github.com/zafrem/privyscope)'s neural NER pipeline, so the Go tools can get entity spans over HTTP. |

## Detection model

Two complementary layers:

- **Stage 1 — regex + verification** (always on): 204 patterns across US, KR, JP,
  CN, TW, IN, EU, ES, FR and common formats. A match that declares a validator
  (Luhn, IBAN mod-97, KR RRN, …) is gated on that checksum, cutting false
  positives; matches score by severity, boosted when a validator confirms them.
- **Stage 2 — neural NER** (opt-in): privyscope's ONNX BIOES model adds
  contextual entities regex misses (names, addresses). Served by the sidecar and
  merged into results, tagged by source. Korean today; en/zh/ja as those model
  packs ship.

## Quick start

```bash
git clone --recurse-submodules <repo-url>
# or, if already cloned:
git submodule update --init --recursive

# Build and run the scanner (regex only)
cd grep-cloud-storage && go build -o grep-cloud-storage . && ./grep-cloud-storage --estimate-only s3://my-bucket/

# Add neural NER: start the sidecar, then pass --ner
cd ../privyscope-ner-server && pip install -r requirements.txt && python server.py &
./grep-cloud-storage/grep-cloud-storage --ner s3://my-bucket/logs/
```

Each tool has its own README with full usage:
[grep-cloud-storage](grep-cloud-storage/README.md) · [privyscope-ner-server](privyscope-ner-server/README.md).

## Layout notes

- The engine is a **submodule at the repository root** so every current and
  future tool can reference the same rule set and validators.
- `grep-cloud-storage`'s Go module uses a `replace` directive to import the engine's
  `verification` package (`pii_verification`) from the submodule, since it is not
  published under a resolvable import path.
- Language plugins for NER (e.g. `privyscope-ko`) are installed into the sidecar,
  not vendored here.
