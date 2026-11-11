"""Capture metadata only; never persist headers, credentials, or request bodies."""
import base64
import binascii
import json
import re
from urllib.parse import unquote, parse_qsl
import time
from pathlib import Path


def response(flow):
    row = {
        'recorded_at_ns': time.time_ns(),
        'diagnostics_revision': 3,
        'http_host': flow.request.host_header,
        'sni': flow.client_conn.sni,
        'tls': flow.client_conn.tls_established,
        'path': flow.request.path.partition('?')[0],
        'method': flow.request.method,
        'host': flow.request.host,
        'content_type': flow.request.headers.get('content-type', ''),
        'content_encoding': flow.request.headers.get('content-encoding', ''),
        'body_bytes': len(flow.request.raw_content or b''),
        'status': flow.response.status_code,
        'content_decodable': None,
        'json_parseable': None,
    }
    try:
        request_text = (flow.request.raw_content or b'').decode('utf-8')
        row['content_decodable'] = True
        try:
            json.loads(request_text)
            row['json_parseable'] = True
        except ValueError as error:
            row['json_parseable'] = False
            row['json_error'] = getattr(error, 'msg', type(error).__name__)
            row['json_error_offset'] = getattr(error, 'pos', None)
            row['body_ascii'] = request_text.isascii()
            row['structural_punctuation'] = sorted(set(char for char in request_text if not char.isalnum()))
            segments = request_text.split('.')
            row['dot_segment_lengths'] = [len(part) for part in segments][:6]
            if len(segments) in (3, 5):
                try:
                    header = json.loads(base64.urlsafe_b64decode(segments[0] + '=' * (-len(segments[0]) % 4)))
                    row['jose_header'] = {name: value for name, value in header.items() if name in {'alg','enc','typ','zip'} and isinstance(value, str) and len(value) < 32}
                except (ValueError, UnicodeError, binascii.Error, AttributeError):
                    row['jose_header_parseable'] = False
            row['colon_count'] = request_text.count(':')
            row['newline_count'] = request_text.count('\n')
            row['urlsafe_base64_alphabet'] = bool(re.fullmatch(r'[A-Za-z0-9_+/=-]+', request_text))
            row['form_field_names'] = [name if name in {'data', 'payload', 'body', 'request'} else '<other>' for name, _ in parse_qsl(request_text)][:4]
            try:
                json.loads(unquote(request_text))
                row['url_decoded_json'] = True
            except ValueError:
                row['url_decoded_json'] = False
            try:
                decoded = base64.b64decode(request_text, validate=True)
                row['base64_valid'] = bool(request_text)
                row['decoded_bytes'] = len(decoded)
                try:
                    json.loads(decoded)
                    row['base64_json_parseable'] = True
                except (ValueError, UnicodeError):
                    row['base64_json_parseable'] = False
            except (ValueError, binascii.Error):
                row['base64_valid'] = False
    except UnicodeError:
        row['content_decodable'] = False
    try:
        body = json.loads(flow.response.content)
        if isinstance(body, dict) and body.get('source') == 'agent-sec-gateway':
            row['gateway_error'] = body.get('error')
    except (ValueError, TypeError):
        pass
    with Path('/opt/asc-demo/gateway-conf/metadata.jsonl').open('a') as out:
        out.write(json.dumps(row) + '\n')
