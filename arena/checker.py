"""Trusted driver. Run only inside an offline Ukai jail; candidate code is hostile."""
import json
import subprocess
import sys


# The trusted parent, not the imported candidate, decides whether outputs match.
# -I ignores PYTHONPATH, startup hooks and the current-directory import path.
cases = [("Hello World", "hello-world"), ("  Ship   It  ", "ship-it"),
         ("top 10 tips", "top-10-tips"), ("", ""),
         ("MiXeD\tText\nHere", "mixed-text-here")]
child = """import importlib.util,json,sys
s=importlib.util.spec_from_file_location('candidate',sys.argv[1])
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
print(json.dumps(m.slugify(json.loads(sys.argv[2]))))
"""
results = []
for value, expected in cases:
    try:
        p = subprocess.run([sys.executable, "-I", "-B", "-c", child,
                            sys.argv[1], json.dumps(value)], capture_output=True,
                           timeout=3, text=True)
        actual = json.loads(p.stdout) if len(p.stdout) <= 4096 else None
        passed = p.returncode == 0 and actual == expected
    except (ValueError, subprocess.TimeoutExpired):
        passed = False
    results.append(passed)
print(json.dumps({"schema": "arena.task-check/1", "passed": all(results),
                  "cases_passed": sum(results), "cases_total": len(results)}))
sys.exit(0 if all(results) else 1)
