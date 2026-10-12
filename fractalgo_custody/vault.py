"""FractalGo custody prototype: encrypted snapshots with optimistic concurrency.

Not an integration into G14's browser storage. No original data or keys included.
AEAD authenticates records and their lineage. A retained external receipt is
needed to detect rollback to an otherwise valid earlier database snapshot.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import re
import sqlite3
import stat
import sys
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

FORMAT = 'fractalgo-vault/1'
ITERATIONS = 600_000
MAX_BYTES = 32 * 1024 * 1024
IDENTIFIER = re.compile(r'^[0-9a-f]{32}$')
DIGEST = re.compile(r'^[0-9a-f]{64}$')
ZERO = '0' * 64
CHECK = b'FractalGo custody key confirmation v1'


class VaultError(Exception):
    """A rejected operation; no claim of source truth or identity."""


class Conflict(VaultError):
    pass


class Locked(VaultError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('utf-8')


def strict_json(data: bytes) -> object:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise VaultError('DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    def constant(_):
        raise VaultError('NONFINITE_JSON')
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=pairs,
                          parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise VaultError('INVALID_JSON') from exc


def check_id(value: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise VaultError('INVALID_IDENTIFIER')
    return value


def derive(password: str, salt: bytes) -> bytes:
    if not isinstance(password, str):
        raise VaultError('INVALID_PASSWORD')
    data = password.encode('utf-8')
    if len(password) < 14 or len(data) > 1024:
        raise VaultError('PASSWORD_LENGTH_14_TO_1024_UTF8_BYTES')
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=ITERATIONS).derive(data)


def create_private_file(path: Path) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    flags |= getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, 0o600)
    os.close(fd)


def check_file(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise VaultError('REGULAR_FILE_REQUIRED')
    if os.name == 'posix' and info.st_mode & 0o077:
        raise VaultError('PRIVATE_FILE_PERMISSIONS_REQUIRED')


@dataclass(frozen=True)
class Receipt:
    vault_id: str
    record_id: str
    sequence: int
    revision_id: str
    parent: str
    digest: str

    @classmethod
    def load(cls, data: bytes) -> 'Receipt':
        obj = strict_json(data)
        if not isinstance(obj, dict) or set(obj) != set(cls.__dataclass_fields__):
            raise VaultError('INVALID_RECEIPT')
        for field in ('vault_id', 'record_id', 'revision_id'):
            check_id(obj[field])
        if type(obj['sequence']) is not int or obj['sequence'] < 1:
            raise VaultError('INVALID_RECEIPT')
        if any(not isinstance(obj[k], str) or not DIGEST.fullmatch(obj[k])
               for k in ('parent', 'digest')):
            raise VaultError('INVALID_RECEIPT')
        return cls(**obj)


class Vault:
    """Single-machine encrypted revision store; one instance per calling thread.

    Receives opaque bytes, not scientific evidence. The application must validate
    its own workspace contracts before saving and after restoring. No plaintext
    content, title, document name or content hash is inserted into SQL.
    """
    def __init__(self, path: Path, vault_id: str, key: bytes):
        self.path = path
        self.vault_id = vault_id
        self._aead: AESGCM | None = AESGCM(key)

    @classmethod
    def create(cls, path: str | Path, password: str) -> 'Vault':
        path = Path(path).absolute()
        salt = os.urandom(32)
        key = derive(password, salt)
        vid = uuid.uuid4().hex
        header = canonical({'format': FORMAT, 'vault_id': vid,
                            'kdf': 'PBKDF2-SHA256', 'iterations': ITERATIONS,
                            'salt': salt.hex()})
        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, CHECK, header)
        create_private_file(path)
        try:
            with cls(path, vid, key)._connection() as db:
                db.executescript('''
                BEGIN IMMEDIATE;
                CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
                CREATE TABLE heads (
                  record_id TEXT PRIMARY KEY, sequence INTEGER NOT NULL,
                  digest TEXT NOT NULL);
                CREATE TABLE revisions (
                  record_id TEXT NOT NULL, sequence INTEGER NOT NULL,
                  revision_id TEXT UNIQUE NOT NULL, parent TEXT NOT NULL,
                  nonce BLOB UNIQUE NOT NULL, ciphertext BLOB NOT NULL,
                  digest TEXT NOT NULL,
                  PRIMARY KEY(record_id, sequence));
                COMMIT;
                ''')
                db.execute('BEGIN IMMEDIATE')
                for k, v in [('header', header), ('nonce', nonce), ('check', ct)]:
                    db.execute('INSERT INTO meta VALUES (?,?)', (k, v))
                db.commit()
        except BaseException:
            # Never delete a pre-existing file. This path was created exclusively.
            path.unlink(missing_ok=True)
            raise
        return cls(path, vid, key)

    @classmethod
    def open(cls, path: str | Path, password: str) -> 'Vault':
        path = Path(path).absolute()
        check_file(path)
        db = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)
        try:
            rows = db.execute('SELECT key,value FROM meta').fetchall()
        except sqlite3.Error as exc:
            raise VaultError('INVALID_VAULT') from exc
        finally:
            db.close()
        meta = dict(rows)
        if set(meta) != {'header', 'nonce', 'check'}:
            raise VaultError('INVALID_HEADER')
        header = meta['header']
        if not isinstance(header, bytes) or len(header) > 4096:
            raise VaultError('INVALID_HEADER')
        obj = strict_json(header)
        if (not isinstance(obj, dict) or set(obj) !=
            {'format', 'vault_id', 'kdf', 'iterations', 'salt'} or
            obj['format'] != FORMAT or obj['kdf'] != 'PBKDF2-SHA256' or
            type(obj['iterations']) is not int or obj['iterations'] != ITERATIONS or
            not isinstance(obj['salt'], str) or
            not DIGEST.fullmatch(obj['salt'])):
            raise VaultError('UNSUPPORTED_HEADER')
        check_id(obj['vault_id'])
        if (not isinstance(meta['nonce'], bytes) or len(meta['nonce']) != 12 or
            not isinstance(meta['check'], bytes) or len(meta['check']) != len(CHECK)+16):
            raise VaultError('INVALID_HEADER')
        key = derive(password, bytes.fromhex(obj['salt']))
        try:
            value = AESGCM(key).decrypt(meta['nonce'], meta['check'], header)
        except InvalidTag as exc:
            raise VaultError('PASSWORD_OR_INTEGRITY_FAILURE') from exc
        if value != CHECK:
            raise VaultError('KEY_CONFIRMATION_FAILURE')
        return cls(path, obj['vault_id'], key)

    def lock(self) -> None:
        # Removes this reference, not a promise of forensic memory erasure.
        self._aead = None

    def _ready(self) -> AESGCM:
        if self._aead is None:
            raise Locked('VAULT_LOCKED')
        return self._aead

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        self._ready()
        check_file(self.path)
        db = sqlite3.connect(self.path.as_uri() + '?mode=rw', uri=True,
                             timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA trusted_schema=OFF')
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA synchronous=FULL')
        db.execute('PRAGMA temp_store=MEMORY')
        try:
            yield db
        finally:
            if db.in_transaction:
                db.rollback()
            db.close()

    def _aad(self, rid: str, seq: int, rev: str, parent: str) -> bytes:
        return canonical([FORMAT, self.vault_id, rid, seq, rev, parent])

    def _decode(self, row: sqlite3.Row) -> tuple[bytes, Receipt]:
        check_id(row['record_id'])
        check_id(row['revision_id'])
        if type(row['sequence']) is not int or row['sequence'] < 1:
            raise VaultError('INVALID_SEQUENCE')
        if not isinstance(row['parent'], str) or not DIGEST.fullmatch(row['parent']):
            raise VaultError('INVALID_PARENT')
        nonce, ct = row['nonce'], row['ciphertext']
        if (not isinstance(nonce, bytes) or len(nonce) != 12 or
            not isinstance(ct, bytes) or not 17 <= len(ct) <= MAX_BYTES+16):
            raise VaultError('INVALID_RECORD_SIZE')
        aad = self._aad(row['record_id'], row['sequence'], row['revision_id'], row['parent'])
        digest = hashlib.sha256(aad + nonce + ct).hexdigest()
        if digest != row['digest']:
            raise VaultError('CIPHERTEXT_HASH_MISMATCH')
        try:
            raw = self._ready().decrypt(nonce, ct, aad)
        except InvalidTag as exc:
            raise VaultError('RECORD_AUTHENTICATION_FAILURE') from exc
        return raw, Receipt(self.vault_id, row['record_id'], row['sequence'],
                            row['revision_id'], row['parent'], digest)

    def _verify(self, db: sqlite3.Connection, rid: str,
                anchor: Receipt | None = None) -> list[Receipt]:
        check_id(rid)
        rows = db.execute('SELECT * FROM revisions WHERE record_id=? ORDER BY sequence',
                          (rid,)).fetchall()
        head = db.execute('SELECT * FROM heads WHERE record_id=?', (rid,)).fetchone()
        receipts = []
        previous = ZERO
        for expected, row in enumerate(rows, 1):
            _, receipt = self._decode(row)
            if receipt.sequence != expected or receipt.parent != previous:
                raise VaultError('BROKEN_LINEAGE')
            receipts.append(receipt)
            previous = receipt.digest
        if not receipts:
            if head is not None or anchor is not None:
                raise VaultError('MISSING_HISTORY')
            return []
        if head is None or head['sequence'] != len(receipts) or head['digest'] != previous:
            raise VaultError('HEAD_MISMATCH')
        if anchor is not None:
            if (anchor.vault_id != self.vault_id or anchor.record_id != rid or
                anchor.sequence > len(receipts) or receipts[anchor.sequence-1] != anchor):
                raise VaultError('EXTERNAL_ANCHOR_MISMATCH')
        return receipts

    def save(self, content: bytes, *, record_id: str | None = None,
             expected_tip: str | None = None, request_id: str | None = None) -> Receipt:
        self._ready()
        if not isinstance(content, bytes) or not 1 <= len(content) <= MAX_BYTES:
            raise VaultError('CONTENT_SIZE_OR_TYPE')
        rid = check_id(record_id or uuid.uuid4().hex)
        revision = check_id(request_id or uuid.uuid4().hex)
        if expected_tip is not None and (not isinstance(expected_tip, str) or
                                        not DIGEST.fullmatch(expected_tip)):
            raise VaultError('INVALID_EXPECTED_TIP')
        with self._connection() as db:
            db.execute('BEGIN IMMEDIATE')
            history = self._verify(db, rid)
            existing = db.execute('SELECT * FROM revisions WHERE revision_id=?',
                                  (revision,)).fetchone()
            if existing is not None:
                prior, receipt = self._decode(existing)
                if (receipt.record_id == rid and receipt.parent == (expected_tip or ZERO)
                    and prior == content):
                    db.commit()
                    return receipt
                raise Conflict('REQUEST_ID_REUSED_WITH_DIFFERENT_CONTENT')
            actual = history[-1].digest if history else None
            if actual != expected_tip:
                raise Conflict('STALE_HEAD_NO_OVERWRITE')
            seq, parent = len(history)+1, actual or ZERO
            aad = self._aad(rid, seq, revision, parent)
            # Fresh 96-bit nonce; uniqueness checked against this key's persisted uses.
            for _ in range(10):
                nonce = os.urandom(12)
                used = db.execute('SELECT 1 FROM revisions WHERE nonce=?', (nonce,)).fetchone()
                check_nonce = db.execute("SELECT value FROM meta WHERE key='nonce'").fetchone()[0]
                if used is None and nonce != check_nonce:
                    break
            else:
                raise VaultError('NONCE_GENERATION_FAILURE')
            ciphertext = self._ready().encrypt(nonce, content, aad)
            digest = hashlib.sha256(aad + nonce + ciphertext).hexdigest()
            db.execute('INSERT INTO revisions VALUES (?,?,?,?,?,?,?)',
                       (rid, seq, revision, parent, nonce, ciphertext, digest))
            db.execute('INSERT INTO heads VALUES (?,?,?) ON CONFLICT(record_id) '
                       'DO UPDATE SET sequence=excluded.sequence,digest=excluded.digest',
                       (rid, seq, digest))
            db.commit()
            return Receipt(self.vault_id, rid, seq, revision, parent, digest)

    def history(self, record_id: str, *, anchor: Receipt | None = None) -> list[Receipt]:
        with self._connection() as db:
            db.execute('BEGIN')
            return self._verify(db, record_id, anchor)

    def read(self, record_id: str, *, sequence: int | None = None,
             anchor: Receipt | None = None) -> tuple[bytes, Receipt]:
        with self._connection() as db:
            db.execute('BEGIN')
            history = self._verify(db, record_id, anchor)
            if not history:
                raise VaultError('NOT_FOUND')
            seq = len(history) if sequence is None else sequence
            if type(seq) is not int or not 1 <= seq <= len(history):
                raise VaultError('UNKNOWN_REVISION')
            row = db.execute('SELECT * FROM revisions WHERE record_id=? AND sequence=?',
                             (record_id, seq)).fetchone()
            return self._decode(row)

    def records(self) -> list[str]:
        with self._connection() as db:
            return [r[0] for r in db.execute('SELECT record_id FROM heads ORDER BY record_id')]

    def verify_all(self) -> dict:
        with self._connection() as db:
            db.execute('BEGIN')
            ids = {r[0] for r in db.execute('SELECT record_id FROM heads')}
            ids |= {r[0] for r in db.execute('SELECT DISTINCT record_id FROM revisions')}
            count = sum(len(self._verify(db, rid)) for rid in ids)
            return {'vault_id': self.vault_id, 'records': len(ids), 'revisions': count,
                    'content_authenticated': True, 'external_freshness_verified': False,
                    'scientific_validity_verified': False}

    def backup(self, destination: str | Path) -> None:
        target = Path(destination).absolute()
        create_private_file(target)
        try:
            with self._connection() as src:
                src.execute('BEGIN')
                ids = {r[0] for r in src.execute('SELECT record_id FROM heads')}
                ids |= {r[0] for r in src.execute('SELECT DISTINCT record_id FROM revisions')}
                for rid in ids:
                    self._verify(src, rid)
                dst = sqlite3.connect(target)
                try:
                    src.backup(dst)
                finally:
                    dst.close()
        except BaseException:
            target.unlink(missing_ok=True)
            raise


def main() -> int:
    parser = argparse.ArgumentParser(description='FractalGo: custodia cifrada local, sin integración UI todavía')
    parser.add_argument('operation', choices=['init','put','get','list','verify','backup'])
    parser.add_argument('database', type=Path)
    parser.add_argument('--input', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--record')
    parser.add_argument('--expect', help='Hash del último recibo; necesario para añadir una revisión')
    parser.add_argument('--request', help='UUID hexadecimal para reintentar sin duplicar')
    parser.add_argument('--sequence', type=int)
    parser.add_argument('--anchor', type=Path, help='Recibo anterior conservado por otro canal')
    args = parser.parse_args()
    password = getpass.getpass('Contraseña de la bóveda (mínimo 14 caracteres): ')
    vault = None
    try:
        if args.operation == 'init':
            if password != getpass.getpass('Repetir contraseña: '):
                raise VaultError('PASSWORDS_DIFFER')
            vault = Vault.create(args.database, password)
            print(json.dumps({'vault_id': vault.vault_id, 'created': True}))
            return 0
        vault = Vault.open(args.database, password)
        anchor = Receipt.load(args.anchor.read_bytes()) if args.anchor else None
        if args.operation == 'put':
            if args.input is None:
                raise VaultError('INPUT_REQUIRED')
            with args.input.open('rb') as source:
                raw = source.read(MAX_BYTES+1)
            receipt = vault.save(raw, record_id=args.record, expected_tip=args.expect,
                                 request_id=args.request)
            print(json.dumps(asdict(receipt), sort_keys=True))
        elif args.operation == 'get':
            if args.record is None or args.output is None:
                raise VaultError('RECORD_AND_NEW_OUTPUT_REQUIRED')
            raw, receipt = vault.read(args.record, sequence=args.sequence, anchor=anchor)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
            fd = os.open(args.output, flags, 0o600)
            with os.fdopen(fd, 'wb') as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            print('Atención: el archivo recuperado está en claro. No se borró ningún original.', file=sys.stderr)
            print(json.dumps(asdict(receipt), sort_keys=True))
        elif args.operation == 'list':
            print(json.dumps(vault.records()))
        elif args.operation == 'verify':
            if anchor:
                vault.history(anchor.record_id, anchor=anchor)
            result = vault.verify_all()
            result['retained_anchor_checked'] = anchor is not None
            print(json.dumps(result, sort_keys=True))
        elif args.operation == 'backup':
            if args.output is None:
                raise VaultError('NEW_OUTPUT_REQUIRED')
            vault.backup(args.output)
            print(json.dumps({'backup_created': True, 'encrypted_records': True}))
        return 0
    except (VaultError, OSError, sqlite3.Error) as exc:
        print(f'Operación rechazada: {exc}', file=sys.stderr)
        return 2
    finally:
        if vault:
            vault.lock()


if __name__ == '__main__':
    raise SystemExit(main())
