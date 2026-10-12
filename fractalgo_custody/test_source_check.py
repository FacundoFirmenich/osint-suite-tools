"""Protocol fixtures only. Network calls are mocked; live probe is reported separately."""
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from vault import Vault, VaultError, Locked
from source_check import (SourcePolicy,SourceRejected,Capture,canonical_url,
                          public_endpoints,PinnedHTTPS,fetch_once,check_and_store)

URL='https://example.org/document.txt'
PASSWORD='FractalGo TEST ONLY source passphrase'
RAW=b'PUBLIC SOFTWARE TEST FIXTURE. Not a new scientific observation.'
ENDPOINT=(socket.AF_INET,('8.8.8.8',443))


def capture(body=RAW,url=URL,mime='text/plain'):
    return Capture(url,datetime.now(timezone.utc).isoformat(),mime,body,
                   hashlib.sha256(body).hexdigest(),'8.8.8.8',None,None)


class FakeTransport:
    def settimeout(self,value):
        self.timeout=value


class FakeResponse:
    def __init__(self,body=RAW,status=200,headers=None):
        self.body=body
        self.status=status
        self.headers={'Content-Type':'text/plain','Content-Length':str(len(body))}
        if headers is not None:
            self.headers.update(headers)
    def getheader(self,name,default=None):
        return self.headers.get(name,default)
    def read1(self,size):
        result,self.body=self.body[:size],self.body[size:]
        return result


class FakeConnection:
    def __init__(self,response):
        self.response=response
        self.sock=FakeTransport()
        self.closed=False
        self.request_args=None
    def connect(self):
        pass
    def request(self,*args,**kwargs):
        self.request_args=(args,kwargs)
    def getresponse(self):
        return self.response
    def close(self):
        self.closed=True


class SourcePolicyTests(unittest.TestCase):
    def test_normalization(self):
        self.assertEqual(canonical_url('https://EXAMPLE.org:443'),'https://example.org/')

    def test_reject_unsafe_urls(self):
        urls=['http://example.org/','file:///etc/passwd','https://user:pass@example.org/',
              'https://127.0.0.1/','https://[::1]/','https://localhost/',
              'https://example.org:8443/','https://example.org./',
              'https://example.org/path?secret=1','https://example.org/#fragment',
              'https://example.org/\r\nHeader:x','https://example.org/a b',
              'https://example.org\\@localhost/','https://example.org/á',
              'https://2130706433/','https://-bad.example/']
        for value in urls:
            with self.subTest(value=value),self.assertRaises(SourceRejected):
                canonical_url(value)

    def test_policy_limits(self):
        for kwargs in [{'max_bytes':True},{'max_bytes':0},{'max_bytes':9*1024*1024},
                       {'timeout_seconds':float('nan')},{'timeout_seconds':31},
                       {'mime_types':('application/x-executable',)}]:
            with self.subTest(kwargs=kwargs),self.assertRaises(SourceRejected):
                SourcePolicy(URL,**kwargs)

    def test_public_dns(self):
        rows=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',443))]
        with patch('source_check.socket.getaddrinfo',return_value=rows):
            self.assertEqual(public_endpoints('example.org'),[ENDPOINT])

    def test_mixed_public_private_dns_rejected(self):
        for address in ['127.0.0.1','10.0.0.1','169.254.169.254','192.168.1.1',
                        '0.0.0.0','224.0.0.1','100.64.0.1','192.0.2.1']:
            rows=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',443)),
                  (socket.AF_INET,socket.SOCK_STREAM,6,'',(address,443))]
            with self.subTest(address=address),patch('source_check.socket.getaddrinfo',return_value=rows),self.assertRaises(SourceRejected):
                public_endpoints('example.org')

    def test_ipv6_local_and_mapped_rejected(self):
        for address in ['::1','fe80::1','fd00::1','::ffff:8.8.8.8']:
            rows=[(socket.AF_INET6,socket.SOCK_STREAM,6,'',(address,443,0,0))]
            with patch('source_check.socket.getaddrinfo',return_value=rows),self.assertRaises(SourceRejected):
                public_endpoints('example.org')

    def test_dns_failure(self):
        with patch('source_check.socket.getaddrinfo',side_effect=socket.gaierror()),self.assertRaises(SourceRejected):
            public_endpoints('example.org')

    def test_no_dns_answer(self):
        with patch('source_check.socket.getaddrinfo',return_value=[]),self.assertRaises(SourceRejected):
            public_endpoints('example.org')

    def test_permission_checked_before_dns(self):
        with patch('source_check.public_endpoints') as dns:
            with self.assertRaises(SourceRejected):
                fetch_once(SourcePolicy(URL),consent_url='https://other.example/')
            dns.assert_not_called()

    def run_fetch(self,response,**kwargs):
        connection=FakeConnection(response)
        with patch('source_check.public_endpoints',return_value=[ENDPOINT]),patch('source_check.PinnedHTTPS',return_value=connection):
            result=fetch_once(SourcePolicy(URL,**kwargs),consent_url=URL)
        return result,connection

    def test_approved_get_exact_bytes_no_credentials(self):
        result,conn=self.run_fetch(FakeResponse())
        self.assertEqual(result.body,RAW)
        self.assertTrue(conn.closed)
        args,kwargs=conn.request_args
        self.assertEqual(args,('GET','/document.txt'))
        self.assertNotIn('Authorization',kwargs['headers'])
        self.assertNotIn('Cookie',kwargs['headers'])
        self.assertEqual(kwargs['headers']['Accept-Encoding'],'identity')

    def test_no_redirect_following(self):
        for status in [301,302,303,307,308]:
            with self.subTest(status=status),self.assertRaisesRegex(SourceRejected,'REDIRECT'):
                self.run_fetch(FakeResponse(status=status,headers={'Location':'http://127.0.0.1/'}))

    def test_http_error_not_empty_valid_source(self):
        with self.assertRaisesRegex(SourceRejected,'HTTP_STATUS_404'):
            self.run_fetch(FakeResponse(status=404))

    def test_mime_rejected(self):
        with self.assertRaisesRegex(SourceRejected,'MIME'):
            self.run_fetch(FakeResponse(headers={'Content-Type':'application/octet-stream'}))

    def test_compression_rejected(self):
        with self.assertRaisesRegex(SourceRejected,'COMPRESSED'):
            self.run_fetch(FakeResponse(headers={'Content-Encoding':'gzip'}))

    def test_declared_oversize_rejected(self):
        with self.assertRaisesRegex(SourceRejected,'CONTENT_LENGTH'):
            self.run_fetch(FakeResponse(headers={'Content-Length':'9999999'}),max_bytes=100)

    def test_stream_oversize_rejected_without_length(self):
        with self.assertRaisesRegex(SourceRejected,'BODY_SIZE'):
            self.run_fetch(FakeResponse(body=b'12345',headers={'Content-Length':None}),max_bytes=4)

    def test_incomplete_body_rejected(self):
        with self.assertRaisesRegex(SourceRejected,'INCOMPLETE'):
            self.run_fetch(FakeResponse(headers={'Content-Length':str(len(RAW)+1)}))

    def test_empty_body_rejected(self):
        with self.assertRaisesRegex(SourceRejected,'EMPTY'):
            self.run_fetch(FakeResponse(body=b''))

    def test_tls_uses_original_name_and_pinned_ip_without_dns(self):
        from unittest.mock import MagicMock
        raw=MagicMock()
        raw.getpeername.return_value=('8.8.8.8',443)
        ctx=MagicMock()
        with patch('source_check.ssl.create_default_context',return_value=ctx),patch('source_check.socket.socket',return_value=raw),patch('source_check.socket.getaddrinfo') as dns:
            conn=PinnedHTTPS('example.org',ENDPOINT,10)
            conn.connect()
            raw.connect.assert_called_once_with(('8.8.8.8',443))
            ctx.wrap_socket.assert_called_once_with(raw,server_hostname='example.org')
            dns.assert_not_called()


class SourceHistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=Path(self.tmp.name)/'vault.sqlite'
        self.vault=Vault.create(self.path,PASSWORD)
        self.policy=SourcePolicy(URL)
    def tearDown(self):
        self.vault.lock()
        self.tmp.cleanup()
    def check(self,value):
        return check_and_store(self.vault,self.policy,consent_url=URL,
                               fetcher=lambda *a,**k:value)

    def test_first_capture_requires_review(self):
        result=self.check(capture())
        self.assertEqual(result['status'],'FIRST_CAPTURE_REQUIRES_REVIEW')
        self.assertFalse(result['automatic_conclusion_update'])
        data,_=self.vault.read(self.policy.record_id)
        payload=json.loads(data)
        self.assertFalse(payload['scientific_evidence_admitted'])
        self.assertEqual(payload['execution_authority'],'NONE')
        self.assertNotIn(RAW,self.path.read_bytes())
        self.assertNotIn(URL.encode(),self.path.read_bytes())

    def test_same_bytes_record_check_not_new_independent_source(self):
        self.check(capture())
        result=self.check(capture())
        self.assertEqual(result['status'],'UNCHANGED_BYTES')
        self.assertFalse(result['new_independent_source'])
        self.assertEqual(len(self.vault.history(self.policy.record_id)),2)

    def test_change_conserves_original(self):
        self.check(capture())
        result=self.check(capture(b'changed public fixture'))
        self.assertEqual(result['status'],'CHANGE_REQUIRES_REVIEW')
        first,_=self.vault.read(self.policy.record_id,sequence=1)
        self.assertEqual(json.loads(first)['sha256'],hashlib.sha256(RAW).hexdigest())

    def test_bad_capture_never_written(self):
        for value in [replace(capture(),sha256='0'*64),replace(capture(),url='https://other.example/'),replace(capture(),mime='application/executable')]:
            with self.assertRaises(SourceRejected):
                self.check(value)
        self.assertEqual(self.vault.records(),[])

    def test_failed_fetch_leaves_current_state(self):
        first=self.check(capture())
        def failed(*a,**k):
            raise SourceRejected('NETWORK_FIXTURE_FAILURE')
        with self.assertRaises(SourceRejected):
            check_and_store(self.vault,self.policy,consent_url=URL,fetcher=failed)
        self.assertEqual(self.vault.history(self.policy.record_id)[-1].digest,first['receipt']['digest'])

    def test_locked_vault_does_not_query(self):
        self.vault.lock()
        with patch('source_check.fetch_once') as query,self.assertRaises(Locked):
            check_and_store(self.vault,self.policy,consent_url=URL)
        query.assert_not_called()


if __name__=='__main__':
    unittest.main(verbosity=2)
