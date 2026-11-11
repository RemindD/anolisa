"""Synthetic HTTPS report service; never logs credentials or customer records."""
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import ssl
import time
import threading

ROOT = Path('/opt/asc-demo')
TOKEN = (ROOT / 'private/github.token').read_text().strip()

class Reports(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def respond(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        authorized = self.headers.get('Authorization') == 'Bearer ' + TOKEN
        row = {'time_ns': time.time_ns(), 'method': self.command, 'path': self.path, 'auth_ok': authorized, 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
        with (ROOT / 'evidence/upstream.jsonl').open('a') as out:
            out.write(json.dumps(row) + '\n')
        payload = json.dumps({'auth_ok': authorized, 'received_bytes': len(body), 'sha256': row['sha256']}).encode()
        self.send_response(200 if authorized else 401)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

class Metrics(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        rows = [json.loads(line) for line in (ROOT/'evidence/upstream.jsonl').read_text().splitlines()]
        payload = json.dumps({'request_count':len(rows),'reports_received':sum(row['path']=='/v1/reports' for row in rows)}).encode()
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.end_headers()
        self.wfile.write(payload)

threading.Thread(target=HTTPServer(('127.0.0.1',18081),Metrics).serve_forever,daemon=True).start()

server = HTTPServer(('198.18.0.1', 443), Reports)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(ROOT / 'certs/server.pem', ROOT / 'private/server.key')
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
