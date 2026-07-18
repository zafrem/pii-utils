# privyscope NER sidecar

A small HTTP service that runs [privyscope](https://github.com/zafrem/privyscope)'s
two-stage (regex + ONNX NER) pipeline, so tools written in other languages —
notably [`aws-s3-grep`](../aws-s3-grep) — can obtain PII entity spans over HTTP.

The model (`klue/roberta-base` for Korean) caps NER input at **256 tokens** and
privyscope's `redact()` truncates rather than chunks. This server does
**token-based windowing** with the model's own tokenizer so long inputs are
fully covered, then maps window-local offsets back to absolute character offsets
and de-duplicates across the overlaps.

## Install & run

```bash
pip install -r requirements.txt        # privyscope + a language pack + ONNX stack
python server.py                       # http://127.0.0.1:8080
```

The first request downloads model weights from Hugging Face (e.g.
`zafrem/privyscope-ko`) into `~/.cache/privyscope`. For offline/air-gapped use,
point `PRIVYSCOPE_CACHE_DIR` at a directory that already contains a bundle
(`privyscope_meta.json`, `*.onnx`, `tokenizer*`).

### Configuration (env)

| Variable | Default | Meaning |
|----------|---------|---------|
| `PRIVYSCOPE_LANG` | *(auto)* | Fix one language (e.g. `ko`); unset = auto-route per text across installed packs |
| `PRIVYSCOPE_OPERATING_POINT` | `balanced` | Recall/precision trade-off passed to privyscope |
| `PRIVYSCOPE_CACHE_DIR` | — | Local weights bundle (enables fully offline start) |
| `NER_WINDOW_OVERLAP_TOKENS` | `32` | Token overlap between windows |
| `NER_HOST` / `NER_PORT` | `127.0.0.1` / `8080` | Bind address |

Adding `en`/`zh`/`ja` later is just `pip install privyscope-en …`; auto mode
picks them up with no server change.

## API

```
GET /health
  → {"status":"ok","has_ner":true,"languages":["ko"],"operating_point":"balanced"}

POST /analyze
  body: {"texts": ["홍길동의 전화번호는 010-1234-5678"], "operating_point": "balanced"}
  → {"schema":1,"results":[{"spans":[
        {"label":"PER","start":0,"end":3,"text":"홍길동"},
        {"label":"PHONE","start":10,"end":23,"text":"010-1234-5678"}
     ]}]}
```

`start`/`end` are **character** offsets into the corresponding input text
(`end` exclusive). `aws-s3-grep`'s client converts these to byte offsets to line
up with its regex findings.

## Notes

- The server uses only the Python standard library (`http.server`,
  `ThreadingHTTPServer`); ONNX Runtime releases the GIL during inference, so
  threaded requests run in parallel.
- Windowing reaches into privyscope internals (`_runtime.tokenizer`,
  `_runtime.max_length`) to size windows precisely. If privyscope later exposes
  a public long-text API, switch to it here.
