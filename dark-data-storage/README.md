# dark-data-storage

Discover ungoverned ("dark") storage in an AWS account and scan it for
personally identifiable information (PII). Where
[`grep-cloud-storage`](../grep-cloud-storage) scans one bucket you point it at,
`dark-data-storage` **finds** the buckets worth worrying about — the public,
unencrypted, and untagged ones you may have forgotten — and then samples them
for PII.

It is a standalone CLI. There is no server, agent, or manager: it runs locally,
uses your ambient AWS credentials, and writes its output to a local session
directory.

## What it does

1. **Enumerates every bucket** the caller owns (`s3:ListAllMyBuckets`) and, for
   each one, **audits its posture**:
   - **Exposure** — public via bucket policy (`s3:GetBucketPolicyStatus`) or ACL
     grants to `AllUsers`/`AuthenticatedUsers` (`s3:GetBucketAcl`), taking any
     Public Access Block (`s3:GetPublicAccessBlock`) into account.
   - **Governance** — default encryption (`s3:GetBucketEncryption`) and tagging
     (`s3:GetBucketTagging`).
   - **Region** (`s3:GetBucketLocation`) and an approximate object count.
2. **Scores and ranks** each bucket into a risk tier (low → critical). Public
   exposure dominates; missing encryption and tags stack on top. A bucket it
   could not fully audit (e.g. `AccessDenied` on a sub-API) is treated as
   suspicious, not assumed safe. The ranked audit is printed and written to
   `discovery.json`.
3. **Selects the dark buckets** — anything with an exposure or governance gap is
   flagged and scanned by default (`--all-buckets` scans everything; `--min-tier`
   raises the bar).
4. **Samples each selected bucket for PII** using the shared
   [pii-pattern-engine](https://github.com/zafrem/pii-pattern-engine) rules
   (regex + checksum verification), capped at `--sample` objects per bucket so a
   discovery sweep stays cheap. Each bucket is scanned in its own region.
5. **Warns on cost, rate-limits, and resumes** exactly like `grep-cloud-storage`:
   a token-bucket limiter on every S3 call, a cost estimate + prompt before a
   large scan, and an append-only session ledger that lets an interrupted run
   pick up where it left off.
6. **Optional NER stage** (`--ner`) adds neural entity detection via the
   [privyscope sidecar](../privyscope-ner-server), merged with regex findings
   (regex wins on overlap).

## Quick start

```bash
git submodule update --init --recursive   # fetch pii-pattern-engine
cd dark-data-storage
go build -o dark-data-storage .

# Audit only — rank the dark-data surface, write discovery.json, scan nothing
./dark-data-storage --discover-only

# Discover + scan the flagged (ungoverned) buckets for PII
./dark-data-storage

# Scan everything, but only 100 objects per bucket, non-interactive
./dark-data-storage --all-buckets --sample 100 --yes

# Only look at buckets whose name contains "logs", high-risk and up
./dark-data-storage --filter logs --min-tier high
```

Requires AWS credentials via the standard chain (env, profile, or instance
role) and a region (`--region` or `AWS_REGION`). Needs `s3:ListAllMyBuckets`,
`s3:GetBucketLocation`, `s3:GetBucketAcl`, `s3:GetBucketPolicyStatus`,
`s3:GetPublicAccessBlock`, `s3:GetBucketEncryption`, `s3:GetBucketTagging`,
`s3:ListBucket`, `s3:GetObject`, and `sts:GetCallerIdentity`. Buckets it cannot
fully audit are reported (and flagged), never silently skipped.

## Risk scoring

| Signal | Points | Notes |
|--------|--------|-------|
| Publicly accessible | +60 | via policy and/or ACL, unless a Public Access Block neutralizes it |
| No default encryption | +25 | only when confirmed absent |
| Untagged / ungoverned | +15 | only when confirmed absent |
| Audit incomplete | +10 | a property could not be read (treated as suspicious) |

Tiers: `critical` ≥ 60, `high` ≥ 40, `medium` ≥ 20, else `low`. A bucket is
**flagged** (and scanned by default) if it has any confirmed exposure/governance
gap or could not be fully audited. Fully-governed buckets (private, encrypted,
tagged, fully audited) are not flagged.

Unverified is not the same as absent: if the audit could not read a bucket's
encryption or tags, that missing signal does **not** add the "unencrypted"/
"untagged" points — only the "audit incomplete" point — so a bucket is never
penalized for a property we simply couldn't see.

## Session directory (discovery report + resumable scan)

Each run uses a session directory (`--out`, or an auto-derived
`darkdata-<account>-<fingerprint>/` so re-running resumes):

```
<session>/
  discovery.json   the ranked audit of every discovered bucket
  manifest.json    run metadata + a fingerprint of the account and selection
  results.jsonl    append-only ledger, one Record per scanned object
                   (keyed "bucket/key"), flushed as it happens
  summary.json     aggregate counts, (re)written at finish or on interrupt
```

The ledger namespaces keys by bucket (`bucket/key`), so a resume across many
buckets skips exactly what was already processed. The cost warning applies to
the **remaining** objects across all selected buckets.

## Layout

```
pii-pattern-engine/            # git submodule (shared by all tools in this repo)
dark-data-storage/
  main.go                      # CLI + orchestration (discover → assess → scan)
  internal/discovery/          # provider-neutral risk scoring + selection (pure, unit-tested)
  internal/awsx/               # clients, caller identity, per-bucket audit
  internal/cost/               # cost estimate + thresholds
  internal/provider/           # object-storage abstraction: S3Store (+ rate limit) and an in-memory fake
  internal/scanner/            # concurrent GET/scan pipeline (sampling) over a provider.Store
  internal/engine/             # YAML loader, matcher, scoring, verification gate
  internal/ner/                # privyscope NER sidecar client
  internal/report/             # summary + JSON report
  internal/session/            # append-only ledger + resume
  tests/                       # black-box tests (discovery, detection, cost, session)
```

The Go module uses a `replace` directive pointing `pii_verification` at
`../pii-pattern-engine/verification/golang`, since that package is not published
under a resolvable import path.

## Key flags

| Flag | Default | Purpose |
|------|---------|---------|
| `--discover-only` | off | audit + write `discovery.json`, then exit (no scanning) |
| `--all-buckets` | off | scan every bucket, not just the flagged ones |
| `--min-tier` | — | only scan buckets at/above `low\|medium\|high\|critical` |
| `--filter` | — | only consider buckets whose name contains this substring |
| `--sample` | `500` | max objects scanned per bucket (0 = all) |
| `--audit-list` | `1000` | objects LISTed per bucket for an approximate count (0 = skip) |
| `--rps` / `--burst` | `20` / `5` | S3 API rate limit (0 = unlimited) |
| `--concurrency` | `8` | concurrent object downloads |
| `--max-object-mb` | `100` | skip objects larger than this |
| `--scan-cap-kb` | `0` | read at most N KB per object (0 = whole object) |
| `--ner` | off | enable the privyscope NER stage (needs the sidecar) |
| `--ner-endpoint` | `http://127.0.0.1:8080` | sidecar base URL |
| `--ner-max-kb` | `256` | cap text (KB) sent to NER per object |
| `--out` / `--fresh` | auto / off | session dir for the resumable ledger / restart it |
| `--warn-objects` / `--warn-gb` / `--warn-usd` | `100000` / `50` / `10` | cost-warning thresholds |
| `--yes` | off | proceed past the cost warning without prompting |
| `--json` | — | also write a copy of `summary.json` to this path |

## Notes

- Raw matched values are **never** emitted; findings carry a mask only.
- Only the caller's own account is enumerated — `ListBuckets` cannot see other
  accounts' buckets. "Dark data" here means shadow storage *within* your account.
- The cost estimate is approximate (standard-tier list prices) and intended as
  an upper-bound guardrail, not a billing figure.
