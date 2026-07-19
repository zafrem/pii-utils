# grep-cloud-storage

Scan objects under an AWS S3 prefix for personally identifiable information
(PII) using the [pii-pattern-engine](https://github.com/zafrem/pii-pattern-engine)
rules (regex + checksum verification), with safeguards for large-scale scans.

Point it at a bucket/prefix you already know. To instead **discover** which
buckets are ungoverned and worth scanning, see the sibling tool
[`dark-data-storage`](../dark-data-storage).

> Despite the "cloud-storage" name, only AWS S3 is implemented today. The code
> is AWS-only (the AWS SDK is its sole cloud dependency); GCS/Azure are not
> supported.

## What it does

1. **Loads detection rules** from the `pii-pattern-engine` regex YAML files and
   wires each rule's checksum/validator (Luhn, IBAN, RRN, …) from the engine's
   Go `verification` package. Rules whose validator passes score higher;
   matches that fail their checksum are dropped as false positives.
2. **Identifies the caller** (`sts:GetCallerIdentity`) and performs a
   **same-account check** against the bucket owner's canonical ID
   (`s3:GetBucketAcl`). Cross-account or indeterminate ownership prints a
   warning; `--require-same-account` turns it into a hard stop.
3. **Estimates cost** from a LIST inventory (GET/LIST request cost, plus an
   internet-egress upper bound when the scan is cross-account) and **warns +
   prompts** before scanning when the volume crosses a threshold.
4. **Rate-limits every S3 call** through a shared token bucket
   (`--rps`/`--burst`) and layers the SDK's adaptive retry/backoff on top, so a
   large scan does not trip S3 request throttling (503 SlowDown).
5. **Writes results continuously and resumes.** Every scan runs against a
   **session directory** and appends one JSON line per object to
   `results.jsonl` as it completes (flushed immediately). If the run is
   interrupted (Ctrl-C, crash, spot reclaim), re-running the same command
   resumes: it re-lists the bucket, skips objects already in the ledger, and
   keeps appending. Nothing already written is lost or re-scanned.
6. **Optional NER stage** (`--ner`) adds neural entity detection via the
   [privyscope NER sidecar](../privyscope-ner-server) (names, addresses, and
   other contextual PII the regex rules miss). NER findings are tagged
   `source:"ner"` and merged with regex findings; where both fire on the same
   span the regex finding wins (it has a pattern id, checksum verification, and
   a calibrated score).

## NER (optional)

`--ner` sends each object's text to the privyscope sidecar and merges the
returned entities. Start the sidecar first (see
[`privyscope-ner-server/`](../privyscope-ner-server)):

```bash
cd privyscope-ner-server && pip install -r requirements.txt && python server.py
```

Then:

```bash
grep-cloud-storage --ner s3://my-bucket/logs/
```

- The tool preflights `GET /health` and **fails fast** (before any AWS call) if
  the sidecar is down.
- Text sent per object is capped by `--ner-max-kb` (default 256) — a 256-token
  transformer over large volumes is expensive, so this bounds per-object cost.
- If a NER call fails mid-scan, that object is still recorded with its regex
  findings and the run continues; the summary reports how many objects fell back
  to regex-only.
- Korean works today (`zafrem/privyscope-ko`); en/zh/ja light up automatically
  as those language packs are installed on the sidecar.

## Session directory (continuous output + resume)

Each run uses a session directory (`--out`, or an auto-derived
`s3grep-<bucket>-<fingerprint>/` so re-running the same command resumes):

```
<session>/
  manifest.json    run metadata + a fingerprint of the target and pattern
                   selection (a resume that doesn't match is refused)
  results.jsonl    append-only ledger, one Record per processed object,
                   flushed as it happens — the live report and the checkpoint
  summary.json     aggregate counts, (re)written at finish or on interrupt
```

Because the aggregate summary is reconstructed by replaying the ledger, it is
correct even across many resumes. Tail the report live with:

```bash
tail -f <session>/results.jsonl | jq 'select(.findings | length > 0)'
```

Resume semantics:
- The cost warning applies to the **remaining** objects, not the whole job.
- A truncated final line (hard crash mid-write) is tolerated on replay.
- `--fresh` archives the prior ledger/manifest aside and starts over.
- Objects recorded with an error are treated as done (not retried on resume).

## Layout

```
pii-pattern-engine/            # git submodule (shared by all tools in this repo)
grep-cloud-storage/
  main.go                      # CLI + orchestration
  internal/engine/             # YAML loader, matcher, scoring, verification gate
  internal/awsx/               # clients, caller identity, same-account check
  internal/cost/               # cost estimate + thresholds
  internal/scanner/            # rate-limited LIST + concurrent GET/scan
  internal/ner/                # privyscope NER sidecar client
  internal/report/             # human summary + JSON report
  internal/session/            # append-only ledger + resume
  tests/                       # black-box tests (detection, cost, session)
```

The Go module uses a `replace` directive pointing `pii_verification` at
`../pii-pattern-engine/verification/golang`, since that package is not published
under a resolvable import path.

## Setup

```bash
git submodule update --init --recursive   # fetch pii-pattern-engine
cd grep-cloud-storage
go build -o grep-cloud-storage .
```

Patterns are auto-detected from the submodule; override with `--patterns` or
`PII_PATTERNS_DIR`.

## Usage

```bash
# Estimate only — list + cost, no downloads
grep-cloud-storage --estimate-only s3://my-bucket/logs/

# Scan, throttled to 20 req/s, write a JSON report
grep-cloud-storage --rps 20 --concurrency 8 --json findings.json s3://my-bucket/logs/

# Only Korean + common credit-card rules, hard-stop on cross-account
grep-cloud-storage --locations kr,comm --categories credit_card \
  --require-same-account s3://my-bucket/

# Non-interactive (CI): skip the large-scan prompt
grep-cloud-storage --yes s3://my-bucket/
```

Requires AWS credentials via the standard chain (env, profile, or instance
role) and a region (`--region` or `AWS_REGION`). Needs `s3:ListBucket`,
`s3:GetObject`, `s3:GetBucketAcl`, and `sts:GetCallerIdentity`.

### Key flags

| Flag | Default | Purpose |
|------|---------|---------|
| `--rps` / `--burst` | `20` / `5` | S3 API rate limit (0 = unlimited) |
| `--concurrency` | `8` | concurrent object downloads |
| `--max-object-mb` | `100` | skip objects larger than this |
| `--scan-cap-kb` | `0` | read at most N KB per object (0 = whole object) |
| `--require-same-account` | off | abort if bucket is not same-account |
| `--ner` | off | enable the privyscope NER stage (needs the sidecar) |
| `--ner-endpoint` | `http://127.0.0.1:8080` | sidecar base URL |
| `--ner-max-kb` | `256` | cap text (KB) sent to NER per object |
| `--out` / `--fresh` | auto / off | session dir for the resumable ledger / restart it |
| `--warn-objects` / `--warn-gb` / `--warn-usd` | `100000` / `50` / `10` | cost-warning thresholds |
| `--yes` | off | proceed past the cost warning without prompting |
| `--json` | — | also write a copy of `summary.json` to this path |

## Notes

- Raw matched values are **never** emitted; findings carry a mask only.
- Object contents are matched grep-style; binary-looking objects are skipped
  unless `--scan-binary` is set.
- The cost estimate is approximate (standard-tier us-east-1 list prices) and
  intended as an upper-bound guardrail, not a billing figure.
