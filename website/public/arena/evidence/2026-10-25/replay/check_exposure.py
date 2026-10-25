"""Offline replay of selected redacted exposure evidence; no network or model calls."""
import json
from pathlib import Path
from m1.adapters import exposure
rows=json.loads((Path(__file__).parent/'exposure-cases.json').read_text())
for row in rows:
    observed=exposure(row['transcript'],row['expected_path'],row['workspace'],row['fixture'],row['nonce'])
    assert observed['status']==row['expected_status'], (row['run_id'],observed)
    print(row['run_id'],observed['status'])
print(f'{len(rows)} exposure cases verified; no policy or containment replay performed.')
