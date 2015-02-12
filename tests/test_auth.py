from unittest import TestCase
from mock import patch, Mock
from pycclib.cclib import API, APIException


class APIAuthTestCase(TestCase):
    api = API(url='any.url')


class SSHTokenTestCase(APIAuthTestCase):
    @patch('pycclib.cclib.httplib2._parse_www_authenticate')
    @patch('pycclib.cclib.httplib2.Http')
    def test_should_return_ssh_token(self, h, p):
        p.return_value = dict(Basic=dict(realm="API"), ccssh=dict(sshtoken='1234'))
        h.return_value.request.return_value = (Mock(status=401), '')

        self.assertEqual('1234', self.api.create_ssh_token())
        self.assertEqual('any.url/token/', h.return_value.request.call_args[0][0])
        self.assertEqual('POST', h.return_value.request.call_args[0][1])
        self.assertEqual('', h.return_value.request.call_args[1]['body'])

    @patch('pycclib.cclib.httplib2._parse_www_authenticate')
    @patch('pycclib.cclib.httplib2.Http')
    def test_should_raise_unauthorized_error_when_missing_ssh_token_in_www_authenticate_header(self, h, p):
        p.return_value = dict(Basic=dict(realm="API"), ccssh=dict(sshtoken=None))
        h.return_value.request.return_value = (Mock(status=401), '')

        self.assertRaises(APIException, self.api.create_ssh_token)
        self.assertEqual('any.url/token/', h.return_value.request.call_args[0][0])
        self.assertEqual('POST', h.return_value.request.call_args[0][1])
        self.assertEqual('', h.return_value.request.call_args[1]['body'])


class TokenTestCase(APIAuthTestCase):
    @patch('pycclib.cclib.httplib2.Http')
    def test_should_return_token_when_auth_with_basic(self, h):
        resp = Mock(status=200)
        h.return_value.request.return_value = (resp, '{\"token\": \"tkn\", \"expires\": \"exp\"}')

        self.assertTrue(True, self.api.create_token_basic_auth('m@n.r', 'pass'))
        self.assertEqual({'expires': 'exp', 'token': 'tkn'}, self.api.get_token())

        self.assertEqual('any.url/token/', h.return_value.request.call_args[0][0])
        self.assertEqual('POST', h.return_value.request.call_args[0][1])

        self.assertEqual('', h.return_value.request.call_args[1]['body'])
        self.assertEqual('Basic bUBuLnI6cGFzcw==', h.return_value.request.call_args[1]['headers']['Authorization'])


    @patch('pycclib.cclib.httplib2.Http')
    def test_should_return_token_when_auth_with_ssh(self, h):
        resp = Mock(status=200)
        h.return_value.request.return_value = (resp, '{\"token\": \"tkn\", \"expires\": \"exp\"}')

        self.assertTrue(True, self.api.create_token_ssh_auth('m@n.r', '1234', 'signature', 'fingerprint'))
        self.assertEqual({'expires': 'exp', 'token': 'tkn'}, self.api.get_token())

        self.assertEqual('any.url/token/', h.return_value.request.call_args[0][0])
        self.assertEqual('POST', h.return_value.request.call_args[0][1])

        self.assertEqual('', h.return_value.request.call_args[1]['body'])
        expected_auth_header = 'ccssh signature=signature,fingerprint=fingerprint,sshtoken=1234,email=m@n.r'
        self.assertEqual(expected_auth_header, h.return_value.request.call_args[1]['headers']['Authorization'])
