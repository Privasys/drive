#!/usr/bin/env python3
"""Docling conversion sidecar for Privasys Drive.

Converts PDF / Office / image files to markdown for the semantic index
(drive plan section 8.2). Runs INSIDE the Drive container next to the Go
service and listens on a UNIX SOCKET only: container apps share the host
network namespace on enclave-os, so a TCP listener would be reachable by
co-located apps (the same lesson as the embedded Postgres). Layout and
table models are baked into the image at build time - no runtime
downloads, so the conversion pipeline is part of the measured image.

Contract (HTTP over the unix socket):
  GET  /healthz            -> {"status": "ok", "docling": "<version>"}
  POST /convert            body = raw file bytes
       X-Filename: <name>  (extension drives format detection)
       -> {"markdown": "...", "pages": <n>} or {"error": "..."}
"""

import json
import os
import socketserver
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler
from pathlib import Path

MAX_BODY = 64 * 1024 * 1024  # matches the drive's upload scale

_converter = None
_convert_lock = threading.Lock()


def build_converter():
    """One DocumentConverter, models from the baked artifacts dir."""
    from docling.datamodel.base_models import InputFormat
    from docling.datamodel.pipeline_options import (
        PdfPipelineOptions,
        TesseractCliOcrOptions,
    )
    from docling.document_converter import DocumentConverter, PdfFormatOption

    artifacts = os.environ.get("DOCLING_ARTIFACTS_PATH")
    # Tesseract via its CLI: an apt package with baked language data —
    # fully offline and far lighter than EasyOCR's torch models.
    ocr = TesseractCliOcrOptions(lang=["eng"])
    pdf_opts = PdfPipelineOptions(
        artifacts_path=artifacts,
        do_ocr=True,
        do_table_structure=True,
        ocr_options=ocr,
    )
    return DocumentConverter(
        format_options={
            InputFormat.PDF: PdfFormatOption(pipeline_options=pdf_opts),
            InputFormat.IMAGE: PdfFormatOption(pipeline_options=pdf_opts),
        }
    )


def get_converter():
    # Caller holds _convert_lock.
    global _converter
    if _converter is None:
        _converter = build_converter()
    return _converter


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # journald via the manager
        sys.stderr.write("docling: " + (fmt % args) + "\n")

    def _reply(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            from importlib.metadata import version

            self._reply(200, {"status": "ok", "docling": version("docling")})
        else:
            self._reply(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/convert":
            self._reply(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            self._reply(413, {"error": "body size out of range"})
            return
        name = self.headers.get("X-Filename", "document.pdf")
        suffix = Path(name).suffix or ".pdf"
        data = self.rfile.read(length)
        try:
            # Docling reads from a path; stage on tmpfs, never persisted.
            with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
                tmp.write(data)
                tmp_path = tmp.name
            try:
                # Model inference is not assumed thread-safe: serialize.
                with _convert_lock:
                    result = get_converter().convert(tmp_path)
                doc = result.document
                markdown = doc.export_to_markdown()
                pages = len(getattr(doc, "pages", {}) or {})
            finally:
                os.unlink(tmp_path)
            self._reply(200, {"markdown": markdown, "pages": pages})
        except Exception as exc:  # noqa: BLE001 - reported to the caller
            self._reply(422, {"error": f"{type(exc).__name__}: {exc}"})


class UnixHTTPServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def get_request(self):
        request, _ = super().get_request()
        # BaseHTTPRequestHandler expects a (host, port) client address.
        return request, ("local", 0)


def main():
    sock = None
    args = sys.argv[1:]
    for i, a in enumerate(args):
        if a == "--socket" and i + 1 < len(args):
            sock = args[i + 1]
    if not sock:
        sys.exit("usage: server.py --socket /path/to.sock")
    Path(sock).parent.mkdir(parents=True, exist_ok=True)
    if os.path.exists(sock):
        os.unlink(sock)
    srv = UnixHTTPServer(sock, Handler)
    os.chmod(sock, 0o600)
    sys.stderr.write(f"docling: serving on {sock}\n")
    srv.serve_forever()


if __name__ == "__main__":
    main()
