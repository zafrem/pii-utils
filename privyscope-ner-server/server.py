#!/usr/bin/env python3
"""privyscope NER sidecar — a small HTTP service that runs privyscope's two-stage
(regex + ONNX NER) pipeline so non-Python tools (e.g. aws-s3-grep) can get PII
spans over HTTP.

Why a sidecar: privyscope's ``redact()`` truncates NER input to the model's
max_length (256 tokens) — it does not chunk. This server does token-based
windowing using the model's own tokenizer so long inputs are fully covered, then
shifts window-local offsets back to absolute character offsets and de-duplicates
across the overlaps.

Endpoints:
  GET  /health   -> {"status","has_ner","languages","operating_point"}
  POST /analyze  -> body {"texts":[str,...], "operating_point"?:str}
                    resp {"schema":1,"results":[{"spans":[{label,start,end,text}]}]}

Config (env):
  PRIVYSCOPE_LANG              fix a single language (e.g. "ko"); default: auto
  PRIVYSCOPE_OPERATING_POINT   "balanced" (default) | "high_recall" | ...
  PRIVYSCOPE_CACHE_DIR         local weights bundle dir (enables offline use)
  NER_WINDOW_OVERLAP_TOKENS    token overlap between windows (default 32)
  NER_HOST / NER_PORT          bind address (default 127.0.0.1 / 8080)

Run:
  pip install privyscope privyscope-ko onnxruntime transformers tokenizers huggingface_hub
  python server.py            # or: NER_PORT=9000 python server.py
"""
from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SCHEMA = 1
OVERLAP_TOKENS = int(os.environ.get("NER_WINDOW_OVERLAP_TOKENS", "32"))


def build_engine():
    """Construct the privyscope engine from env, preloading weights."""
    try:
        from privyscope import Privyscope
    except ImportError as exc:  # pragma: no cover
        sys.exit(
            "error: privyscope is not installed.\n"
            "  pip install privyscope <language-pack>   (e.g. privyscope-ko)\n"
            f"  ({exc})"
        )

    op = os.environ.get("PRIVYSCOPE_OPERATING_POINT", "balanced")
    cache_dir = os.environ.get("PRIVYSCOPE_CACHE_DIR") or None
    lang = os.environ.get("PRIVYSCOPE_LANG") or None

    if lang:
        engine = Privyscope.from_pretrained(lang=lang, operating_point=op, cache_dir=cache_dir)
        langs = [lang]
    else:
        # Auto-routing across every installed language plugin; preload so the
        # first request is warm and missing weights fail fast at startup.
        auto = Privyscope.auto(operating_point=op, cache_dir=cache_dir).preload()
        engine = auto
        langs = auto.available_languages
    return engine, langs


class Analyzer:
    """Wraps a privyscope engine with token-based windowing for long text."""

    def __init__(self, engine, languages):
        self.engine = engine
        self.languages = languages
        self.has_ner = bool(getattr(engine, "has_ner", False))

    def _runtime_for(self, text):
        """Return the NER runtime (tokenizer holder) for the text's engine, or
        None when running regex-only. Reaches into privyscope internals because
        windowing needs the model's tokenizer and max_length."""
        eng = self.engine
        # AutoPrivyscope: route then fetch the per-language engine.
        if hasattr(eng, "route") and hasattr(eng, "_engine_for"):
            eng = eng._engine_for(eng.route(text))
        return getattr(eng, "_runtime", None)

    def _windows(self, text):
        """Yield (char_start, char_end) windows that each tokenize to at most
        (max_length - 2) tokens, so privyscope never truncates a window."""
        rt = self._runtime_for(text)
        if rt is None or not text:
            return [(0, len(text))]
        enc = rt.tokenizer(text, return_offsets_mapping=True, add_special_tokens=False)
        offsets = enc["offset_mapping"]
        if not offsets:
            return [(0, len(text))]
        win = max(1, int(rt.max_length) - 2)
        stride = max(1, win - OVERLAP_TOKENS)
        out = []
        i = 0
        n = len(offsets)
        while i < n:
            j = min(i + win, n)
            cs = int(offsets[i][0])
            ce = int(offsets[j - 1][1])
            out.append((cs, ce))
            if j >= n:
                break
            i += stride
        return out

    def analyze(self, text, operating_point=None):
        seen = {}
        for cs, ce in self._windows(text):
            sub = text[cs:ce]
            res = self.engine.redact(sub, operating_point=operating_point)
            for s in res.detected_spans:
                start, end = s.start + cs, s.end + cs
                key = (s.label, start, end)
                if key not in seen:
                    seen[key] = {"label": s.label, "start": start, "end": end, "text": text[start:end]}
        return sorted(seen.values(), key=lambda d: (d["start"], d["end"]))


class Handler(BaseHTTPRequestHandler):
    analyzer: Analyzer = None  # set in main()

    def log_message(self, *args):  # quieter default logging
        pass

    def _send(self, code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.rstrip("/") == "/health":
            a = self.analyzer
            self._send(200, {
                "status": "ok",
                "has_ner": a.has_ner,
                "languages": a.languages,
                "operating_point": os.environ.get("PRIVYSCOPE_OPERATING_POINT", "balanced"),
            })
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path.rstrip("/") != "/analyze":
            self._send(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(length) or b"{}")
            texts = req.get("texts", [])
            if not isinstance(texts, list):
                raise ValueError("`texts` must be a list of strings")
            op = req.get("operating_point")
            results = [{"spans": self.analyzer.analyze(t or "", op)} for t in texts]
            self._send(200, {"schema": SCHEMA, "results": results})
        except Exception as exc:  # noqa: BLE001 - report any failure to the client
            self._send(400, {"error": str(exc)})


def main():
    host = os.environ.get("NER_HOST", "127.0.0.1")
    port = int(os.environ.get("NER_PORT", "8080"))

    print(f"loading privyscope engine (lang={os.environ.get('PRIVYSCOPE_LANG') or 'auto'}) ...", flush=True)
    engine, langs = build_engine()
    Handler.analyzer = Analyzer(engine, langs)
    print(f"ready: languages={langs} has_ner={Handler.analyzer.has_ner}", flush=True)

    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    print(f"listening on http://{host}:{port}  (POST /analyze, GET /health)", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("shutting down", flush=True)
        httpd.shutdown()


if __name__ == "__main__":
    main()
