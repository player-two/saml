import unittest

import saml

response = None


def setUpModule():
    saml.init("/home/jordan/dev/saml/data/")
    global response
    response = saml.doc_read_file("/home/jordan/dev/saml/lua/t/data/response.xml")


class TestSessionIndex(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.no_index = saml.doc_read_memory('''<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">

    def test_returns_nil_if_no_attribute(self):
  <saml:Assertion>
    <saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z">
    </saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>''')

    def test_returns_none_if_no_attribute(self):
        index = saml.doc_session_index(self.no_index)
        self.assertIsNone(index)

    def test_returns_value_if_attribute(self):
        index = saml.doc_session_index(response)
        self.assertEqual(index, "_be9967abd904ddcae3c0eb4189adbe3f71e327cf93")


class TestAttrs(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.no_attrs = saml.doc_read_memory('''<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:AttributeStatement>
    </saml:AttributeStatement>
  <saml:Assertion>
  </saml:Assertion>
</samlp:Response>''')

    def test_returns_empty_table_when_no_attributes(self):
        attrs = saml.doc_attrs(self.no_attrs)
        self.assertDictEqual({}, attrs)

    def test_returns_all_attributes(self):
        attrs = saml.doc_attrs(response)
        self.assertDictEqual({
            'uid': 'test',
            'mail': 'test@example.com',
            'eduPersonAffiliation': [ 'users', 'examplerole1' ]
        }, attrs)


class TestIssuer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.no_issuer = saml.doc_read_memory('''<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
</samlp:Response>''')

    def test_returns_none_if_no_issuer(self):
        issuer = saml.doc_issuer(self.no_issuer)
        self.assertIsNone(issuer)

    def test_returns_value_of_element(self):
        issuer = saml.doc_issuer(response)
        self.assertEqual('http://idp.example.com/metadata.php', issuer)
