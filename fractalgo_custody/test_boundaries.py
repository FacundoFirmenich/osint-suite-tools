"""Additional contract regressions; no private data or measured phenomena."""
from dataclasses import replace
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import test_source_check as fakes
from source_check import SourcePolicy,SourceRejected,fetch_once,check_and_store
from vault import Vault,Conflict,VaultError


class BoundaryTests(unittest.TestCase):
    def test_http_content_length_completion_does_not_retouch_closed_socket(self):
        class Transport:
            closed=False
            def settimeout(self,_):
                if self.closed:
                    raise OSError('Bad file descriptor: response completed')
        class Response(fakes.FakeResponse):
            def read1(self,n):
                output=super().read1(n)
                if not self.body:
                    transport.closed=True
                return output
        transport=Transport()
        connection=fakes.FakeConnection(Response())
        connection.sock=transport
        with patch('source_check.public_endpoints',return_value=[fakes.ENDPOINT]),patch('source_check.PinnedHTTPS',return_value=connection):
            result=fetch_once(SourcePolicy(fakes.URL),consent_url=fakes.URL)
        self.assertEqual(result.body,fakes.RAW)
        self.assertTrue(connection.closed)

    def test_source_identifiers_do_not_reveal_url_by_deterministic_hash(self):
        a,b=SourcePolicy(fakes.URL),SourcePolicy(fakes.URL)
        self.assertNotEqual(a.record_id,b.record_id)
        self.assertEqual(SourcePolicy(fakes.URL,source_id=a.record_id).record_id,a.record_id)

    def test_deleted_record_not_resurrected_by_stale_writer(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'vault.sqlite'
            v=Vault.create(path,fakes.PASSWORD)
            first=v.save(fakes.RAW)
            with sqlite3.connect(path) as db:
                db.execute('DELETE FROM revisions')
                db.execute('DELETE FROM heads')
            with self.assertRaises(Conflict):
                v.save(b'stale content',record_id=first.record_id,expected_tip=first.digest)
            self.assertEqual(v.records(),[])
            v.lock()

    def test_policy_identity_cannot_be_reused_for_another_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            v=Vault.create(Path(tmp)/'vault.sqlite',fakes.PASSWORD)
            a=SourcePolicy(fakes.URL)
            check_and_store(v,a,consent_url=fakes.URL,fetcher=lambda *args,**kwargs:fakes.capture())
            b=replace(a,url='https://another.example/document')
            with patch('source_check.fetch_once') as query,self.assertRaises(SourceRejected):
                check_and_store(v,b,consent_url=b.url)
            query.assert_not_called()
            v.lock()

    def test_source_concurrent_update_rejected_after_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            v=Vault.create(Path(tmp)/'vault.sqlite',fakes.PASSWORD)
            policy=SourcePolicy(fakes.URL)
            check_and_store(v,policy,consent_url=fakes.URL,fetcher=lambda *a,**k:fakes.capture())
            def racing_fetch(*args,**kwargs):
                check_and_store(v,policy,consent_url=fakes.URL,fetcher=lambda *a,**k:fakes.capture(b'other writer'))
                return fakes.capture(b'late response')
            with self.assertRaises(Conflict):
                check_and_store(v,policy,consent_url=fakes.URL,fetcher=racing_fetch)
            self.assertEqual(len(v.history(policy.record_id)),2)
            v.lock()


if __name__=='__main__':
    unittest.main(verbosity=2)
