from unittest import TestCase
from pycclib.cclib import API


class TestAPI(TestCase):
    def test_token_source_url_fallback(self):
        self.assertEquals('my.tokensource.url',
                          API(url='any.url', token_source_url='my.tokensource.url').token_source_url)
        self.assertEquals('my.api.url/token/', API(url='my.api.url').token_source_url)

    def test_create_token_with_tokensouce_url(self):
        API(url='any.url', token_source_url='my.tokensource.url')

    def test_encode_email(self):
        self.assertEquals(True, API(encode_email=True).encode_email)
        self.assertEquals(False, API(encode_email=False).encode_email)
