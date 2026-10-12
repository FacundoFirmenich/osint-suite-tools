"""Run only this isolated module's tests and emit factual machine-readable evidence."""
from __future__ import annotations
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import sqlite3
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
OUT = ROOT / 'evidence'
OUT.mkdir(exist_ok=True)
start = datetime.datetime.now(datetime.timezone.utc).isoformat()
with (OUT / 'unittest.txt').open('w', encoding='utf-8') as stream:
    suite = unittest.defaultTestLoader.discover(str(ROOT), pattern='test_*.py')
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
report = {
    'schema': 'fractalgo-custody-test-run/1',
    'commit': os.environ.get('GITHUB_SHA'),
    'run_id': os.environ.get('GITHUB_RUN_ID'),
    'started_utc': start,
    'finished_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'python': sys.version,
    'platform': platform.platform(),
    'sqlite': sqlite3.sqlite_version,
    'tests_run': result.testsRun,
    'failures': len(result.failures),
    'errors': len(result.errors),
    'skipped': len(result.skipped),
    'successful': result.wasSuccessful(),
    'case_failures': [{'test': str(case), 'traceback': trace}
                      for case, trace in result.failures + result.errors],
    'boundaries': {
        'original_g14_application_modified': False,
        'original_g14_regression_suite_executed': False,
        'browser_integration_executed': False,
        'private_user_data_used': False,
        'new_scientific_observations': 0,
        'independent_security_audit': False,
        'rollback_detection_requires_external_receipt': True,
    },
}
(OUT/'validation.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
(OUT/'dependencies.txt').write_text(subprocess.check_output(
    [sys.executable,'-m','pip','freeze'],text=True),encoding='utf-8')
manifest = {}
for path in sorted(ROOT.rglob('*')):
    if path.is_file() and '__pycache__' not in path.parts and path.name != 'manifest.json':
        manifest[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
(OUT/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
print((OUT/'unittest.txt').read_text())
print(json.dumps(report,indent=2))
raise SystemExit(0 if result.wasSuccessful() else 1)
