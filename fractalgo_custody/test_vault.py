"""Software fixtures only: no measurements, private workspaces or user keys."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from dataclasses import asdict
from unittest.mock import patch

from vault import (Vault, VaultError, Conflict, Locked, Receipt, MAX_BYTES,
                   ZERO, canonical, strict_json)

PASSWORD = 'FractalGo TEST ONLY long passphrase 2026'
RAW = 'PUBLIC SOFTWARE FIXTURE — title, sources, revisions; not scientific evidence.'.encode()


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'vault.sqlite'
        self.v = Vault.create(self.path, PASSWORD)

    def tearDown(self):
        self.v.lock()
        self.tmp.cleanup()

    def first(self):
        return self.v.save(RAW)

    def test_exact_bytes_after_close_and_open(self):
        r = self.first()
        self.v.lock()
        reopened = Vault.open(self.path, PASSWORD)
        self.assertEqual(reopened.read(r.record_id), (RAW, r))

    def test_new_revision_preserves_prior(self):
        a = self.first()
        b = self.v.save(RAW+b' second', record_id=a.record_id, expected_tip=a.digest)
        self.assertEqual(self.v.read(a.record_id, sequence=1), (RAW, a))
        self.assertEqual(self.v.read(a.record_id), (RAW+b' second', b))
        self.assertEqual(b.sequence, 2)
        self.assertEqual(b.parent, a.digest)

    def test_stale_write_cannot_overwrite(self):
        a = self.first()
        b = self.v.save(b'B', record_id=a.record_id, expected_tip=a.digest)
        with self.assertRaises(Conflict):
            self.v.save(b'C', record_id=a.record_id, expected_tip=a.digest)
        self.assertEqual(self.v.read(a.record_id), (b'B', b))

    def test_existing_record_requires_expected_head(self):
        a = self.first()
        with self.assertRaises(Conflict):
            self.v.save(b'C', record_id=a.record_id)
        self.assertEqual(len(self.v.history(a.record_id)), 1)

    def test_identical_retry_is_idempotent(self):
        rid, req = 'a'*32, 'b'*32
        a = self.v.save(RAW, record_id=rid, request_id=req)
        b = self.v.save(RAW, record_id=rid, request_id=req)
        self.assertEqual(a, b)
        self.assertEqual(len(self.v.history(rid)), 1)

    def test_request_identifier_cannot_change_content(self):
        a = self.v.save(RAW, record_id='a'*32, request_id='b'*32)
        with self.assertRaises(Conflict):
            self.v.save(b'changed', record_id=a.record_id, request_id=a.revision_id)
        self.assertEqual(len(self.v.history(a.record_id)), 1)

    def test_retry_after_later_commit_returns_original_receipt(self):
        a = self.v.save(RAW, record_id='a'*32, request_id='b'*32)
        self.v.save(b'second', record_id=a.record_id, expected_tip=a.digest)
        retry = self.v.save(RAW, record_id=a.record_id, request_id=a.revision_id)
        self.assertEqual(retry, a)
        self.assertEqual(len(self.v.history(a.record_id)), 2)

    def test_request_id_cannot_move_between_records(self):
        self.v.save(RAW, record_id='a'*32, request_id='b'*32)
        with self.assertRaises(Conflict):
            self.v.save(RAW, record_id='c'*32, request_id='b'*32)
        self.assertNotIn('c'*32, self.v.records())

    def test_wrong_password(self):
        self.first()
        with self.assertRaises(VaultError):
            Vault.open(self.path, PASSWORD+'wrong')

    def test_ciphertext_tamper_with_recomputed_hash_still_rejected(self):
        a = self.first()
        with sqlite3.connect(self.path) as db:
            row = db.execute('SELECT nonce,ciphertext FROM revisions').fetchone()
            nonce, cipher = row
            bad = bytes([cipher[0]^1])+cipher[1:]
            aad = self.v._aad(a.record_id, 1, a.revision_id, ZERO)
            digest = hashlib.sha256(aad+nonce+bad).hexdigest()
            db.execute('UPDATE revisions SET ciphertext=?,digest=?', (bad,digest))
            db.execute('UPDATE heads SET digest=?', (digest,))
        with self.assertRaisesRegex(VaultError, 'AUTHENTICATION'):
            self.v.read(a.record_id)

    def test_parent_tamper_rejected(self):
        a = self.first()
        with sqlite3.connect(self.path) as db:
            db.execute('UPDATE revisions SET parent=?', ('f'*64,))
        with self.assertRaises(VaultError):
            self.v.read(a.record_id)

    def test_removed_middle_revision_rejected(self):
        a = self.first()
        self.v.save(b'second', record_id=a.record_id, expected_tip=a.digest)
        with sqlite3.connect(self.path) as db:
            db.execute('DELETE FROM revisions WHERE sequence=1')
        with self.assertRaisesRegex(VaultError, 'BROKEN_LINEAGE'):
            self.v.read(a.record_id)

    def test_head_tamper_rejected(self):
        a = self.first()
        with sqlite3.connect(self.path) as db:
            db.execute('UPDATE heads SET sequence=99')
        with self.assertRaisesRegex(VaultError, 'HEAD_MISMATCH'):
            self.v.history(a.record_id)

    def test_no_plaintext_content_or_plaintext_hash_in_database(self):
        self.first()
        for p in Path(self.tmp.name).iterdir():
            stored = p.read_bytes()
            self.assertNotIn(RAW, stored)
            self.assertNotIn(hashlib.sha256(RAW).hexdigest().encode(), stored)
        # This checks these fixtures, not universal forensic non-disclosure.

    def test_fresh_nonces_for_identical_content(self):
        a = self.first()
        self.v.save(RAW, record_id=a.record_id, expected_tip=a.digest)
        with sqlite3.connect(self.path) as db:
            rows = db.execute('SELECT nonce,ciphertext FROM revisions ORDER BY sequence').fetchall()
        self.assertNotEqual(rows[0][0], rows[1][0])
        self.assertNotEqual(rows[0][1], rows[1][1])

    def test_nonce_collision_fails_closed(self):
        a = self.first()
        with sqlite3.connect(self.path) as db:
            nonce = db.execute('SELECT nonce FROM revisions').fetchone()[0]
        with patch('vault.os.urandom', return_value=nonce):
            with self.assertRaisesRegex(VaultError, 'NONCE_GENERATION'):
                self.v.save(b'second', record_id=a.record_id, expected_tip=a.digest,
                            request_id='d'*32)
        self.assertEqual(len(self.v.history(a.record_id)), 1)

    def test_encryption_failure_rolls_back(self):
        class Broken:
            def encrypt(self, *args):
                raise RuntimeError('INJECTED_TEST_FAILURE')
        aead = self.v._aead
        self.v._aead = Broken()
        with self.assertRaises(RuntimeError):
            self.v.save(RAW)
        self.v._aead = aead
        self.assertEqual(self.v.records(), [])

    def test_backup_recovers_all_bytes(self):
        a = self.first()
        self.v.save(b'second', record_id=a.record_id, expected_tip=a.digest)
        path = Path(self.tmp.name)/'backup.sqlite'
        self.v.backup(path)
        other = Vault.open(path, PASSWORD)
        self.assertEqual(other.read(a.record_id), self.v.read(a.record_id))
        self.assertEqual(other.verify_all()['revisions'], 2)

    def test_backup_never_overwrites_existing_file(self):
        target = Path(self.tmp.name)/'keep.txt'
        target.write_bytes(b'KEEP')
        with self.assertRaises(FileExistsError):
            self.v.backup(target)
        self.assertEqual(target.read_bytes(), b'KEEP')

    def test_rollback_requires_retained_external_anchor(self):
        a = self.first()
        old = Path(self.tmp.name)/'old.sqlite'
        self.v.backup(old)
        b = self.v.save(b'new', record_id=a.record_id, expected_tip=a.digest)
        restored = Vault.open(old, PASSWORD)
        self.assertEqual(restored.read(a.record_id), (RAW,a))
        self.assertFalse(restored.verify_all()['external_freshness_verified'])
        with self.assertRaisesRegex(VaultError, 'EXTERNAL_ANCHOR'):
            restored.read(a.record_id, anchor=b)

    def test_anchor_from_other_vault_rejected(self):
        a = self.first()
        other = Receipt('a'*32, a.record_id, a.sequence, a.revision_id, a.parent,a.digest)
        with self.assertRaises(VaultError):
            self.v.history(a.record_id, anchor=other)

    def test_valid_ancestor_anchor_allows_later_revision(self):
        a = self.first()
        b = self.v.save(b'new', record_id=a.record_id, expected_tip=a.digest)
        self.assertEqual(self.v.read(a.record_id, anchor=a), (b'new', b))

    def test_lock_rejects_read_write_and_backup(self):
        a = self.first()
        self.v.lock()
        for operation in [lambda:self.v.read(a.record_id), lambda:self.v.save(RAW),
                          lambda:self.v.backup(Path(self.tmp.name)/'locked.sqlite')]:
            with self.assertRaises(Locked):
                operation()

    def test_concurrent_writers_only_one_success(self):
        a = self.first()
        barrier = threading.Barrier(2)
        outcomes=[]
        def writer(value):
            v = Vault.open(self.path, PASSWORD)
            barrier.wait(timeout=15)
            try:
                outcomes.append(('ok', v.save(value, record_id=a.record_id,
                                               expected_tip=a.digest)))
            except Conflict:
                outcomes.append(('conflict', None))
            finally:
                v.lock()
        threads=[threading.Thread(target=writer,args=(b'writer-a',)),
                 threading.Thread(target=writer,args=(b'writer-b',))]
        for t in threads:t.start()
        for t in threads:t.join(timeout=20)
        self.assertFalse(any(t.is_alive() for t in threads))
        self.assertEqual(sorted(x[0] for x in outcomes), ['conflict','ok'])
        self.assertEqual(len(self.v.history(a.record_id)),2)

    def test_identifiers_and_sequence_types(self):
        a = self.first()
        for value in ['../x', '', 'not-a-uuid', 'A'*32, True]:
            with self.assertRaises(VaultError):
                self.v.history(value)
        for value in [True,0,-1,99,'1']:
            with self.assertRaises(VaultError):
                self.v.read(a.record_id,sequence=value)

    def test_size_and_type_limits_do_not_write(self):
        for value in [b'', 'string', b'X'*(MAX_BYTES+1)]:
            with self.assertRaises(VaultError):
                self.v.save(value)
        self.assertEqual(self.v.records(),[])

    def test_header_cannot_request_unbounded_kdf(self):
        with sqlite3.connect(self.path) as db:
            raw=db.execute("SELECT value FROM meta WHERE key='header'").fetchone()[0]
            head=json.loads(raw)
            head['iterations']=10**20
            db.execute("UPDATE meta SET value=? WHERE key='header'",(canonical(head),))
        with self.assertRaisesRegex(VaultError, 'UNSUPPORTED_HEADER'):
            Vault.open(self.path,PASSWORD)

    def test_duplicate_json_and_bad_receipts(self):
        with self.assertRaises(VaultError):
            strict_json(b'{"a":1,"a":2}')
        with self.assertRaises(VaultError):
            strict_json(b'{"a":NaN}')
        a = self.first()
        self.assertEqual(Receipt.load(canonical(asdict(a))),a)
        bad=asdict(a);bad['sequence']=True
        with self.assertRaises(VaultError):
            Receipt.load(canonical(bad))

    @unittest.skipUnless(os.name=='posix','POSIX permission checks')
    def test_private_permissions_and_symlink(self):
        self.assertEqual(self.path.stat().st_mode & 0o777,0o600)
        link=Path(self.tmp.name)/'link.sqlite'
        link.symlink_to(self.path)
        with self.assertRaises(VaultError):
            Vault.open(link,PASSWORD)
        os.chmod(self.path,0o644)
        with self.assertRaises(VaultError):
            Vault.open(self.path,PASSWORD)
        os.chmod(self.path,0o600)

    def test_create_never_overwrites(self):
        a = self.first()
        with self.assertRaises(FileExistsError):
            Vault.create(self.path,PASSWORD)
        self.assertEqual(self.v.read(a.record_id),(RAW,a))

    def test_fresh_process_restores_bytes(self):
        a=self.first()
        code='from vault import Vault; import os,sys; v=Vault.open(sys.argv[1],os.environ["FG_TEST_PASSWORD"]); sys.stdout.buffer.write(v.read(sys.argv[2])[0])'
        env=dict(os.environ,FG_TEST_PASSWORD=PASSWORD)
        result=subprocess.run([sys.executable,'-c',code,str(self.path),a.record_id],
                              cwd=Path(__file__).parent,env=env,capture_output=True,check=True)
        self.assertEqual(result.stdout,RAW)


if __name__=='__main__':
    unittest.main(verbosity=2)
