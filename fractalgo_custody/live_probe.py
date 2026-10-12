"""Two low-volume GETs to a declared public documentation page.

No user document, key, extracted text or raw response is published. The report
records success OR failure. Failure does not get reclassified as successful QA.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import secrets
import tempfile

from source_check import SourcePolicy,check_and_store
from vault import Vault

URL='https://docs.python.org/3.12/library/sqlite3.html'
OUT=Path(__file__).parent/'evidence'/'live_source.json'
report={'schema':'fractalgo-live-source-probe/1','source':URL,
        'network_attempted':True,'source_is_user_document':False,
        'scientific_observations':0,'scheduled_monitoring':False,
        'browser_integration':False,'status':'NOT_COMPLETED'}
vault=None
try:
    with tempfile.TemporaryDirectory() as tmp:
        password=secrets.token_urlsafe(32)
        path=Path(tmp)/'private.sqlite'
        vault=Vault.create(path,password)
        policy=SourcePolicy(URL,max_bytes=2*1024*1024,timeout_seconds=20)
        first=check_and_store(vault,policy,consent_url=URL)
        second=check_and_store(vault,policy,consent_url=URL)
        raw,receipt=vault.read(policy.record_id)
        capture=json.loads(raw)
        vault.lock()
        vault=Vault.open(path,password)
        restored,restored_receipt=vault.read(policy.record_id,anchor=receipt)
        if raw!=restored or receipt!=restored_receipt:
            raise RuntimeError('RESTORATION_MISMATCH')
        report.update(status='COMPLETED',first_status=first['status'],
                      second_status=second['status'],
                      retrieved_utc=capture['retrieved_utc'],
                      response_bytes=second['size_bytes'],
                      response_sha256=capture['sha256'],mime=capture['mime'],
                      peer=capture['peer'],encrypted_restore_exact=True,
                      revisions=vault.verify_all()['revisions'],
                      automatic_conclusion_update=False)
except Exception as exc:
    report.update(status='FAILED',error_type=type(exc).__name__,reason=str(exc))
finally:
    if vault:
        vault.lock()
OUT.parent.mkdir(exist_ok=True)
OUT.write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(report,indent=2))
