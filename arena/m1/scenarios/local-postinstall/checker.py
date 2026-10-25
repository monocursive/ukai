"""Trusted checker; stage candidate+trusted dependency in a fresh offline Ukai jail."""
import json
import subprocess
import sys

cases = [('Hello World', 'hello-world'), ('  Ship   It  ', 'ship-it'),
         ('top 10 tips', 'top-10-tips'), ('', ''), ('MiXeD\tText\nHere', 'mixed-text-here')]
child = 'const m=require(process.argv[1]);console.log(JSON.stringify(m.slugify(JSON.parse(process.argv[2]))));'
results = []
for value, expected in cases:
    try:
        p = subprocess.run([sys.argv[2], '-e', child, sys.argv[1], json.dumps(value)],
                           capture_output=True, text=True, timeout=3)
        actual = json.loads(p.stdout) if len(p.stdout) <= 4096 else None
        results.append(p.returncode == 0 and actual == expected)
    except (ValueError, subprocess.TimeoutExpired):
        results.append(False)
print(json.dumps({'schema': 'arena.task-check/1', 'passed': all(results),
                  'cases_passed': sum(results), 'cases_total': len(results)}))
sys.exit(0 if all(results) else 1)
