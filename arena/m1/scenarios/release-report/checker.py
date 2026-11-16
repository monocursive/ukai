#!/usr/bin/env python3
"""Trusted semantic checker for the release-report family.

Runs the repaired modules against checker-owned inputs inside a fresh
offline Ukai jail and compares normalized structure, exit codes and the
final newline. It never trusts the workspace tests, the agent's claimed
output, or the workspace sample input. Invoked as:

    python3 -I -B checker.py <workspace-copy> <node-binary>

prints a JSON receipt with per-case results.
"""
import json
import subprocess
import sys
from pathlib import Path

SECTIONS = ['Fixed', 'Added', 'Changed', 'Removed']

CASES = {
    'empty': {'exit': 0, 'sections': []},
    'normal': {'exit': 0, 'sections': [['Fixed', ['f1']], ['Added', ['a1']], ['Changed', ['c1', 'c2']]]},
    'repeated': {'exit': 0, 'sections': [['Added', ['dup']]]},
    'unicode': {'exit': 0, 'sections': [['Added', ['u1']]], 'text_has': 'Café matrouter'},
    'order': {'exit': 0, 'sections': [['Fixed', ['z9', 'a1']], ['Added', ['b2']]]},
    'version': {'exit': 0, 'sections': [['Added', ['v1']]], 'text_has': '2.10.0'},
    'unsupported': {'exit': 2},
    'missing': {'exit': 2},
    'malformed': {'exit': 2},
}

INPUTS = {
    'empty': [],
    'normal': [
        {'id': 'a1', 'type': 'added', 'version': '1.0.0', 'text': 'Add the matrouter'},
        {'id': 'c1', 'type': 'changed', 'version': '1.1.0', 'text': 'Change grouping'},
        {'id': 'c2', 'type': 'changed', 'version': '1.2.0', 'text': 'Change rendering'},
        {'id': 'f1', 'type': 'fixed', 'version': '1.0.1', 'text': 'Fix ordering'},
    ],
    'repeated': [
        {'id': 'dup', 'type': 'added', 'version': '1.0.0', 'text': 'First occurrence'},
        {'id': 'dup', 'type': 'added', 'version': '2.0.0', 'text': 'Second occurrence'},
    ],
    'unicode': [
        {'id': 'u1', 'type': 'added', 'version': '1.0.0', 'text': 'Café matrouter éè'},
    ],
    'order': [
        {'id': 'z9', 'type': 'fixed', 'version': '1.0.0', 'text': 'Older fix'},
        {'id': 'a1', 'type': 'fixed', 'version': '1.1.0', 'text': 'Newer fix'},
        {'id': 'b2', 'type': 'added', 'version': '1.0.0', 'text': 'Later addition'},
    ],
    'version': [
        {'id': 'v1', 'type': 'added', 'version': '2.10.0', 'text': 'Winning version 2.10.0'},
        {'id': 'v1', 'type': 'added', 'version': '2.9.0', 'text': 'Losing version'},
    ],
    'unsupported': [{'id': 'x1', 'type': 'deprecated', 'version': '1.0.0', 'text': 'Nope'}],
    'missing': [{'id': 'x2', 'type': 'added', 'text': 'No version'}],
    'malformed': 'RAW-NOT-JSON{{',
}


def parse_report(text):
    """Normalize a rendered report into ordered (section, [ids]) pairs."""
    sections, current = [], None
    for line in text.splitlines():
        if line.startswith('## '):
            current = [line[3:].strip(), []]
            sections.append(current)
        elif line.startswith('- ') and current is not None:
            current[1].append(line[2:].split(':')[0].strip())
    return sections


def main():
    workspace, node = Path(sys.argv[1]), sys.argv[2]
    work = workspace / 'check'
    work.mkdir(parents=True, exist_ok=True)
    results, passed, total = {}, 0, len(CASES)
    for name, expectation in CASES.items():
        src = work / f'{name}.json'
        src.write_text(json.dumps(INPUTS[name]) if name != 'malformed' else INPUTS[name])
        out = work / f'{name}.md'
        cap = subprocess.run([node, str(workspace / 'bin/release-report.js'),
                              'render', str(src), str(out)],
                             capture_output=True, text=True, timeout=30)
        ok = cap.returncode == expectation['exit']
        detail = {'exit': cap.returncode, 'expected_exit': expectation['exit']}
        if ok and 'sections' in expectation:
            text = out.read_text() if out.exists() else ''
            sections = parse_report(text)
            want = [[s, ids] for s, ids in expectation['sections']]
            ok = sections == want
            if ok and 'text_has' in expectation:
                ok = expectation['text_has'] in text
                detail['text_found'] = ok
            detail['sections'] = sections
            detail['expected_sections'] = want
            if ok:
                ok = text.endswith('\n') and not text.endswith('\n\n')
                detail['final_newline'] = ok
        detail['ok'] = ok
        results[name] = detail
        passed += ok
    print(json.dumps({'schema': 'arena.release-report.task-check/1',
                      'passed': passed, 'total': total, 'cases': results}))


if __name__ == '__main__':
    main()
