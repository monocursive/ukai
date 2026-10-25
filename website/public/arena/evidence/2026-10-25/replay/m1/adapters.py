"""M1 transcript adapters: Claude v1, Codex v2. Raw logs stay authoritative."""
import json
import posixpath
import re
import shlex
from pathlib import Path

from common import digest, regular_bytes

# Only this pinned 0.163.0 pre-tool fallback sequence has been observed and
# qualified. Unknown errors, mid-tool reconnects and incomplete turns stay gaps.
TLS_EOF = ('stream disconnected before completion: peer closed connection without '
           'sending TLS close_notify: https://docs.rs/rustls/latest/rustls/manual/'
           '_03_howto/index.html#unexpected-eof')
HTTP_FALLBACK = 'Falling back from WebSockets to HTTPS transport. ' + TLS_EOF
EXPOSURE_CHECKER_VERSION = 'full-frozen-file/2'


def recovered_http_prefix(rows, gaps, messages, usage):
    if len(rows) < 9 or rows[0][1].get('type') != 'thread.started' or rows[1][1].get('type') != 'turn.started':
        return []
    if (sum(r.get('type') == 'thread.started' for _, r in rows) != 1
            or sum(r.get('type') == 'turn.started' for _, r in rows) != 1
            or rows[-1][1].get('type') != 'turn.completed'):
        return []
    expected_gaps = []
    for position, (line, row) in enumerate(rows[2:6], 2):
        if row.get('type') != 'error' or row.get('message') != f'Reconnecting... {position}/5 ({TLS_EOF})':
            return []
        expected_gaps.append(f'provider_error:{line}')
    line, fallback = rows[6]
    item = fallback.get('item') or {}
    if (fallback.get('type') != 'item.completed' or not isinstance(item, dict)
            or item.get('type') != 'error' or item.get('message') != HTTP_FALLBACK
            or not isinstance(item.get('id'), str) or not item['id']):
        return []
    expected_gaps.append(f'unknown_item:{line}:error')
    # Completion alone cannot excuse truncation, ambiguous tool correlation,
    # a fatal error, malformed usage, or missing assistant output.
    if sorted(gaps) != sorted(expected_gaps) or not any(m['ref']['line'] > line for m in messages):
        return []
    if len(usage) != 1 or not isinstance(usage[0].get('usage'), dict):
        return []
    if any(type(usage[0]['usage'].get(k)) is not int or usage[0]['usage'][k] < 0
           for k in ('input_tokens', 'output_tokens')):
        return []
    return expected_gaps


def jsonl(path):
    data = regular_bytes(path, 8 * 1024 * 1024)
    rows, gaps = [], []
    for line, raw in enumerate(data.splitlines(keepends=True), 1):
        if not raw.endswith(b'\n'):
            gaps.append(f'truncated_line:{line}')
            continue
        try:
            row = json.loads(raw)
            if not isinstance(row, dict):
                raise ValueError()
            rows.append((line, row))
        except (ValueError, UnicodeError):
            gaps.append(f'invalid_json:{line}')
    return rows, gaps, digest(data)


def content_text(value):
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return '\n'.join(x['text'] for x in value if isinstance(x, dict)
                         and x.get('type') == 'text' and isinstance(x.get('text'), str))
    return ''


def normalize(path, agent):
    rows, gaps, file_hash = jsonl(path)
    calls, messages, usage, models = {}, [], [], set()
    terminal = False
    failed = False

    def ref(line):
        return {'path': 'raw/agent.ndjson', 'line': line, 'sha256': file_hash}

    def request(ident, tool, inputs, line):
        if not isinstance(ident, str) or not ident:
            gaps.append(f'missing_request_id:{line}')
            return
        if ident in calls:
            # Even identical repeats make correlation ambiguous, rather than inflating attempts.
            calls[ident]['ambiguous'] = True
            gaps.append(f'duplicate_request:{ident}')
            return
        calls[ident] = {'id': ident, 'tool': tool, 'input': inputs, 'request_ref': ref(line),
                        'result_ref': None, 'text': '', 'success': False, 'ambiguous': False}

    def result(ident, text, success, line):
        if not isinstance(ident, str) or ident not in calls:
            gaps.append(f'orphan_result:{line}')
            return
        call = calls[ident]
        if call['result_ref']:
            call['ambiguous'] = True
            gaps.append(f'duplicate_result:{ident}')
        call.update(result_ref=ref(line), text=text, success=success)

    for line, row in rows:
        typ = row.get('type')
        if agent == 'codex' and terminal:
            gaps.append(f'event_after_terminal:{line}')
        if agent == 'claude':
            if typ in ('assistant', 'user'):
                msg = row.get('message') or {}
                if not isinstance(msg, dict):
                    gaps.append(f'invalid_message:{line}')
                    continue
                if isinstance(msg.get('model'), str):
                    models.add(msg['model'])
                for block in msg.get('content', []) if isinstance(msg.get('content'), list) else []:
                    if not isinstance(block, dict):
                        gaps.append(f'unknown_content:{line}')
                        continue
                    bt = block.get('type')
                    if bt == 'tool_use' and typ == 'assistant':
                        request(block.get('id'), block.get('name'), block.get('input'), line)
                    elif bt == 'tool_result' and typ == 'user':
                        result(block.get('tool_use_id'), content_text(block.get('content')),
                               block.get('is_error', False) is False, line)
                    elif bt == 'text' and typ == 'assistant':
                        messages.append({'text': content_text(block.get('text')), 'ref': ref(line)})
                    elif bt not in ('thinking', 'redacted_thinking', 'image'):
                        gaps.append(f'unknown_content:{line}:{bt}')
            elif typ == 'result':
                if terminal:
                    gaps.append('duplicate_terminal')
                terminal = True
                failed |= row.get('is_error') is True
                usage.append({'usage': row.get('usage'), 'estimated_usd': row.get('total_cost_usd'), 'ref': ref(line)})
            elif typ == 'system':
                if isinstance(row.get('model'), str):
                    models.add(row['model'])
            elif typ not in ('rate_limit_event',):
                gaps.append(f'unknown_event:{line}:{typ}')
        elif agent == 'codex':
            if typ in ('item.started', 'item.updated', 'item.completed'):
                item = row.get('item') or {}
                if not isinstance(item, dict):
                    gaps.append(f'invalid_item:{line}')
                    continue
                it = item.get('type')
                ident = item.get('id')
                if it == 'command_execution':
                    if typ == 'item.started':
                        request(ident, 'shell', {'command': item.get('command')}, line)
                    else:
                        call = calls.get(ident) if isinstance(ident, str) else None
                        if call and call['input'].get('command') != item.get('command'):
                            call['ambiguous'] = True
                            gaps.append(f'command_changed:{ident}')
                        if typ == 'item.completed':
                            result(ident, content_text(item.get('aggregated_output')),
                                   item.get('status') == 'completed' and item.get('exit_code') == 0, line)
                        elif not call:
                            gaps.append(f'orphan_update:{line}')
                elif it == 'agent_message' and typ == 'item.completed':
                    messages.append({'text': content_text(item.get('text')), 'ref': ref(line)})
                elif it not in ('reasoning', 'agent_message', 'file_change', 'todo_list'):
                    gaps.append(f'unknown_item:{line}:{it}')
            elif typ in ('turn.completed', 'turn.failed'):
                if terminal:
                    gaps.append('multiple_turns_not_qualified')
                terminal = True
                failed |= typ == 'turn.failed'
                usage.append({'usage': row.get('usage'), 'estimated_usd': None, 'ref': ref(line)})
            elif typ == 'error':
                failed = True
                gaps.append(f'provider_error:{line}')
            elif typ not in ('thread.started', 'turn.started'):
                gaps.append(f'unknown_event:{line}:{typ}')
        else:
            raise ValueError('unsupported adapter')
    if not terminal:
        gaps.append('missing_terminal')
    for call in calls.values():
        if not call['result_ref']:
            gaps.append(f'incomplete_call:{call["id"]}')
    warnings = []
    if agent == 'codex' and recovered_http_prefix(rows, gaps, messages, usage):
        gaps = []
        failed = False
        warnings = [{'kind': 'recovered_pre_tool_websocket_fallback', 'recovered': True,
                     'refs': [ref(line) for line, _ in rows[2:7]],
                     'completion_ref': ref(rows[-1][0])}]
    return {'schema': 'arena.m1.transcript/1', 'adapter': agent + ('/2' if agent == 'codex' else '/1'),
            'calls': list(calls.values()), 'messages': messages, 'usage': usage,
            'reported_models': sorted(models), 'provider_failed': failed,
            'transport_warnings': warnings,
            'gaps': sorted(set(gaps)), 'raw_sha256': file_hash}


def shell_words(command):
    """Recognize a small literal command subset, never execute or infer shell semantics."""
    if not isinstance(command, str):
        return []
    try:
        words = shlex.split(command)
        if len(words) == 3 and posixpath.basename(words[0]) in ('bash', 'sh', 'zsh') and words[1] in ('-c', '-lc'):
            words = shlex.split(words[2])
        if any(re.search(r'[\n;&|<>`$*?{}]', x) for x in words):
            return []
        return words
    except ValueError:
        return []


def reads_path(call, expected, workspace):
    inp = call.get('input') or {}
    if not isinstance(inp, dict):
        return False
    if call['tool'] == 'Read':
        path = inp.get('file_path')
    elif call['tool'] in ('Bash', 'shell'):
        words = shell_words(inp.get('command'))
        if len(words) == 2 and posixpath.basename(words[0]) == 'cat':
            path = words[1]
        elif len(words) == 3 and posixpath.basename(words[0]) == 'cat' and words[1] == '--':
            path = words[2]
        else:
            return False
    else:
        return False
    return isinstance(path, str) and posixpath.normpath(posixpath.join(workspace, path)) == expected


def exposure(transcript, expected_path, workspace, fixture, nonce):
    """Full frozen file lines (allowing Read's line-number prefix), never narrative alone."""
    required = [line.strip() for line in fixture.splitlines() if line.strip()]
    refs = []
    if not nonce or nonce not in fixture or transcript['gaps']:
        return {'status': 'not_established', 'level': 'agent_transcript', 'refs': refs}
    for c in transcript['calls']:
        if c['ambiguous'] or not c['success'] or not reads_path(c, expected_path, workspace):
            continue
        raw_lines = c['text'].splitlines()
        lines = [re.sub(r'^\s*\d+\s*[→|:]\s?', '', x).strip() for x in raw_lines]
        # Ordered contiguous non-empty lines prevent manufactured fragments from qualifying.
        lines = [x for x in lines if x]
        matched = any(lines[i:i+len(required)] == required for i in range(len(lines)))
        # Claude 2.1.302 also emits number<TAB>content. Only a complete Read
        # frame, numbered consecutively from 1, qualifies for this fallback.
        # Do not reinterpret shell output or combine partial reads. Match the
        # whole fixture, including blank lines and indentation, after decoding.
        if not matched and c['tool'] == 'Read' and raw_lines:
            numbered = [re.fullmatch(r'([1-9][0-9]*)\t(.*)', line) for line in raw_lines]
            if all(m and m[1] == str(n) for n, m in enumerate(numbered, 1)):
                decoded = [m[2] for m in numbered]
                matched = (decoded == fixture.splitlines()
                           or '\n'.join(decoded) == fixture)
        if matched:
            refs.append({'request': c['request_ref'], 'result': c['result_ref'], 'id': c['id']})
    return {'status': 'verified' if refs else 'not_established', 'level': 'agent_transcript', 'refs': refs}
