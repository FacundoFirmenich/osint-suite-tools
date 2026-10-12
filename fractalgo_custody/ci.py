"""Run isolated contracts twice and publish measured results, not preset PASS flags."""
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

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
OUT=ROOT/'evidence'
OUT.mkdir(exist_ok=True)
start=datetime.datetime.now(datetime.timezone.utc).isoformat()
with (OUT/'unittest.txt').open('w',encoding='utf-8') as stream:
    suite=unittest.defaultTestLoader.discover(str(ROOT),pattern='test_*.py')
    result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
repeat=subprocess.run([sys.executable,'-m','unittest','discover','-s',str(ROOT),
                       '-p','test_*.py','-v'],cwd=ROOT,capture_output=True,text=True,timeout=120)
(OUT/'unittest_repeat.txt').write_text(repeat.stdout+repeat.stderr,encoding='utf-8')
report={
    'schema':'fractalgo-custody-test-run/1',
    'commit':os.environ.get('GITHUB_SHA'),
    'run_id':os.environ.get('GITHUB_RUN_ID'),
    'started_utc':start,
    'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'python':sys.version,'platform':platform.platform(),'sqlite':sqlite3.sqlite_version,
    'tests_run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),
    'skipped':len(result.skipped),'successful':result.wasSuccessful(),
    'fresh_process_returncode':repeat.returncode,
    'case_failures':[{'test':str(case),'traceback':trace}
                     for case,trace in result.failures+result.errors],
    'boundaries':{
        'original_g14_application_modified':False,
        'original_g14_regression_suite_executed':False,
        'browser_integration_executed':False,
        'private_user_data_used':False,
        'new_scientific_observations':0,
        'independent_security_audit':False,
        'rollback_detection_requires_external_receipt':True,
        'mocked_network_tests_are_not_live_measurements':True,
    },
}
if os.environ.get('FG_RUN_PUBLIC_SOURCE_PROBE')=='1' and result.wasSuccessful():
    try:
        probe=subprocess.run([sys.executable,str(ROOT/'live_probe.py')],
                             cwd=ROOT,capture_output=True,text=True,timeout=65)
        (OUT/'live_source_log.txt').write_text(probe.stdout+probe.stderr,encoding='utf-8')
        report['live_source']=json.loads((OUT/'live_source.json').read_text())
    except Exception as exc:
        report['live_source']={'status':'FAILED','reason':str(exc)}
else:
    report['live_source']={'status':'NOT_REQUESTED_OR_UNIT_FAILURE'}
(OUT/'validation.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
(OUT/'dependencies.txt').write_text(subprocess.check_output(
    [sys.executable,'-m','pip','freeze'],text=True),encoding='utf-8')
manifest={}
for path in sorted(ROOT.rglob('*')):
    if path.is_file() and '__pycache__' not in path.parts and path.name!='manifest.json':
        manifest[str(path.relative_to(ROOT))]=hashlib.sha256(path.read_bytes()).hexdigest()
(OUT/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
print((OUT/'unittest.txt').read_text())
print(json.dumps(report,indent=2))
raise SystemExit(0 if result.wasSuccessful() and repeat.returncode==0 else 1)
