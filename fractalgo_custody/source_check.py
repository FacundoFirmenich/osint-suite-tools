"""One explicitly permitted source check, not a crawler or scheduled monitor.

No credentials, proxies, redirects, scripts, HTML rendering or automatic evidence
admission. Bodies are stored only inside the encrypted Vault. URLs and responses
are not uploaded anywhere by this module. Public network destinations can log
that a request occurred. DNS timing depends on the operating-system resolver.
"""
from __future__ import annotations
import argparse
import base64
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import getpass
import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
from urllib.parse import urlsplit, urlunsplit
import uuid

from vault import Vault, VaultError, Receipt, canonical, strict_json

MIMES = frozenset({'text/plain','text/html','text/csv','application/json',
                   'application/pdf','application/xml','text/xml'})
HOST_LABEL = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
MAX_FETCH = 8*1024*1024


class SourceRejected(VaultError):
    pass


def canonical_url(value: str) -> str:
    if (not isinstance(value,str) or not 1 <= len(value) <= 2048 or
        any(ord(c) <= 32 or ord(c) >= 127 for c in value) or '\\' in value):
        raise SourceRejected('URL_REQUIRES_UNAMBIGUOUS_ASCII_ENCODING')
    try:
        u = urlsplit(value)
        port = u.port
    except ValueError as exc:
        raise SourceRejected('INVALID_URL') from exc
    if (u.scheme != 'https' or u.username is not None or u.password is not None or
        not u.hostname or port not in (None,443) or u.fragment or u.query):
        raise SourceRejected('HTTPS_ONLY_NO_CREDENTIALS_QUERY_OR_FRAGMENT')
    host=u.hostname.lower()
    if (len(host)>253 or host.endswith('.') or '.' not in host or
        not all(HOST_LABEL.fullmatch(label) for label in host.split('.'))):
        raise SourceRejected('INVALID_DNS_HOST')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise SourceRejected('IP_LITERAL_NOT_ALLOWED')
    return urlunsplit(('https',host,u.path or '/','',''))


def public_endpoints(host: str) -> list[tuple[int,tuple]]:
    try:
        answers=socket.getaddrinfo(host,443,type=socket.SOCK_STREAM)
    except OSError as exc:
        raise SourceRejected('DNS_FAILED') from exc
    output=[]
    for family,kind,protocol,name,address in answers:
        if family not in (socket.AF_INET,socket.AF_INET6):
            raise SourceRejected('UNSUPPORTED_ADDRESS_FAMILY')
        try:
            ip=ipaddress.ip_address(address[0])
        except ValueError as exc:
            raise SourceRejected('INVALID_DNS_ADDRESS') from exc
        if (not ip.is_global or ip.is_multicast or ip.is_unspecified or
            getattr(ip,'ipv4_mapped',None) is not None):
            raise SourceRejected('NONPUBLIC_DNS_ADDRESS')
        target=(str(ip),443) if family==socket.AF_INET else (str(ip),443,0,0)
        item=(family,target)
        if item not in output:
            output.append(item)
    if not output:
        raise SourceRejected('NO_DNS_ADDRESS')
    return output


class PinnedHTTPS(http.client.HTTPSConnection):
    """Uses the validated numeric address, while verifying the original TLS name."""
    def __init__(self,host: str,endpoint: tuple[int,tuple],timeout: float):
        context=ssl.create_default_context()
        context.set_alpn_protocols(['http/1.1'])
        super().__init__(host,443,timeout=timeout,context=context)
        self.endpoint=endpoint

    def connect(self):
        if self._tunnel_host:
            raise SourceRejected('TUNNELS_DISABLED')
        family,address=self.endpoint
        raw=socket.socket(family,socket.SOCK_STREAM)
        try:
            raw.settimeout(self.timeout)
            raw.connect(address)
            if ipaddress.ip_address(raw.getpeername()[0]) != ipaddress.ip_address(address[0]):
                raise SourceRejected('PEER_ADDRESS_MISMATCH')
            self.sock=self._context.wrap_socket(raw,server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


@dataclass(frozen=True)
class SourcePolicy:
    url: str
    max_bytes: int=2*1024*1024
    timeout_seconds: float=15.0
    mime_types: tuple[str,...]=tuple(sorted(MIMES))

    def __post_init__(self):
        normalized=canonical_url(self.url)
        object.__setattr__(self,'url',normalized)
        if type(self.max_bytes) is not int or not 1<=self.max_bytes<=MAX_FETCH:
            raise SourceRejected('INVALID_SIZE_LIMIT')
        if (type(self.timeout_seconds) not in (int,float) or
            not 0<self.timeout_seconds<=30 or not self.mime_types or
            any(m not in MIMES for m in self.mime_types)):
            raise SourceRejected('INVALID_SOURCE_POLICY')

    @property
    def record_id(self):
        return uuid.uuid5(uuid.NAMESPACE_URL,'fractalgo-source/1:'+self.url).hex


@dataclass(frozen=True)
class Capture:
    url: str
    retrieved_utc: str
    mime: str
    body: bytes
    sha256: str
    peer: str
    etag: str | None
    last_modified: str | None


def fetch_once(policy: SourcePolicy, *, consent_url: str) -> Capture:
    if canonical_url(consent_url) != policy.url:
        raise SourceRejected('EXACT_SOURCE_PERMISSION_REQUIRED')
    u=urlsplit(policy.url)
    endpoints=public_endpoints(u.hostname)
    deadline=time.monotonic()+policy.timeout_seconds
    conn=None
    # Try at most two already validated addresses. Never re-resolve at connect.
    for endpoint in endpoints[:2]:
        remaining=deadline-time.monotonic()
        if remaining<=0:
            raise SourceRejected('FETCH_DEADLINE')
        trial=PinnedHTTPS(u.hostname,endpoint,remaining)
        try:
            trial.connect()
            conn=trial
            break
        except (OSError,ssl.SSLError):
            trial.close()
    if conn is None:
        raise SourceRejected('TLS_CONNECTION_FAILED')
    try:
        conn.request('GET',u.path or '/',headers={
            'User-Agent':'FractalGo-source-check/0.1 (explicit single-source request)',
            'Accept':', '.join(policy.mime_types),
            'Accept-Encoding':'identity',
            'Connection':'close'})
        response=conn.getresponse()
        if 300<=response.status<400:
            raise SourceRejected('REDIRECT_REQUIRES_NEW_PERMISSION')
        if response.status!=200:
            raise SourceRejected('HTTP_STATUS_'+str(response.status))
        if (response.getheader('Content-Encoding','identity').strip().lower()
            not in ('','identity')):
            raise SourceRejected('COMPRESSED_BODY_DISABLED')
        mime=response.getheader('Content-Type','').split(';',1)[0].strip().lower()
        if mime not in policy.mime_types:
            raise SourceRejected('MIME_NOT_PERMITTED')
        length=response.getheader('Content-Length')
        if length is not None and (not length.isdigit() or int(length)>policy.max_bytes):
            raise SourceRejected('CONTENT_LENGTH_LIMIT')
        # HTTPResponse may own the socket after a Connection: close response.
        transport=conn.sock or response.fp.raw._sock
        chunks=[]
        size=0
        while True:
            remaining=deadline-time.monotonic()
            if remaining<=0:
                raise SourceRejected('FETCH_DEADLINE')
            transport.settimeout(remaining)
            part=response.read1(min(65536,policy.max_bytes+1-size))
            if not part:
                break
            chunks.append(part)
            size+=len(part)
            if size>policy.max_bytes:
                raise SourceRejected('BODY_SIZE_LIMIT')
        if length is not None and size!=int(length):
            raise SourceRejected('INCOMPLETE_BODY')
        if not size:
            raise SourceRejected('EMPTY_BODY')
        body=b''.join(chunks)
        return Capture(policy.url,datetime.now(timezone.utc).isoformat(),mime,body,
                       hashlib.sha256(body).hexdigest(),endpoint[1][0],
                       response.getheader('ETag'),response.getheader('Last-Modified'))
    except (OSError,http.client.HTTPException) as exc:
        raise SourceRejected('TRANSPORT_OR_PROTOCOL_FAILURE') from exc
    finally:
        conn.close()


def check_and_store(vault: Vault, policy: SourcePolicy, *, consent_url: str,
                    fetcher=None) -> dict:
    vault._ready()  # No external request when the local vault is locked.
    if canonical_url(consent_url)!=policy.url:
        raise SourceRejected('EXACT_SOURCE_PERMISSION_REQUIRED')
    history=vault.history(policy.record_id)
    previous=None
    if history:
        old,receipt=vault.read(policy.record_id)
        previous=strict_json(old)
        if (not isinstance(previous,dict) or previous.get('schema')!='fractalgo-source-capture/1'
            or previous.get('url')!=policy.url):
            raise SourceRejected('SOURCE_RECORD_COLLISION')
    captured=(fetcher or fetch_once)(policy,consent_url=consent_url)
    if (captured.url!=policy.url or not isinstance(captured.body,bytes) or
        not 0<len(captured.body)<=policy.max_bytes or captured.mime not in policy.mime_types
        or hashlib.sha256(captured.body).hexdigest()!=captured.sha256):
        raise SourceRejected('CAPTURE_CONTRACT_MISMATCH')
    same=previous is not None and previous['sha256']==captured.sha256
    status=('UNCHANGED_BYTES' if same else
            'CHANGE_REQUIRES_REVIEW' if previous else 'FIRST_CAPTURE_REQUIRES_REVIEW')
    payload=asdict(captured)
    payload.pop('body')
    payload.update(schema='fractalgo-source-capture/1',
                   body_base64=base64.b64encode(captured.body).decode('ascii'),
                   comparison=status,source_policy=asdict(policy),
                   scientific_evidence_admitted=False,execution_authority='NONE')
    receipt=vault.save(canonical(payload),record_id=policy.record_id,
                       expected_tip=history[-1].digest if history else None)
    return {'status':status,'receipt':asdict(receipt),'size_bytes':len(captured.body),
            'automatic_conclusion_update':False,'new_independent_source':False,
            'application_integration':False}


def main() -> int:
    p=argparse.ArgumentParser(description='Consultar una URL pública explícita y conservarla cifrada, pendiente de revisión')
    p.add_argument('database')
    p.add_argument('url')
    p.add_argument('--allow-exact-url',required=True)
    a=p.parse_args()
    vault=None
    try:
        policy=SourcePolicy(a.url)
        vault=Vault.open(a.database,getpass.getpass('Contraseña de la bóveda: '))
        result=check_and_store(vault,policy,consent_url=a.allow_exact_url)
        print(json.dumps(result,indent=2))
        return 0
    except (VaultError,OSError) as exc:
        print(json.dumps({'status':'REJECTED','reason':str(exc)}))
        return 2
    finally:
        if vault:
            vault.lock()


if __name__=='__main__':
    raise SystemExit(main())
