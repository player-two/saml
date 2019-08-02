from base64 import b64decode, b64encode
import unittest

import saml

key = None
cert = None
transform_sha256 = None
transform_sha512 = None

binary_data = b'agBv0s1vhMpOxGbsoj1lMPCoYyUOAivpBxZlTyozJcgSmLwCWp1uijM2UTHo'
binary_signature_rsa_sha256 = b'OEBg0Lv7V2aueh5HjiSQJh2Fw5lOm+HPocomlGepvcYAHDcSNXrFmCixOUqmCh9c5Pti3tQ0lOm5qCZ/aMJr7YkTiMYaNE7C3fjYYyDBCj0zoKZIo7UQ966DFe6ezZtBlVUtiuhTcNmeQ67Bk2BE5TRwzKWu0Ahy2LICzQC99gOtzfGgU+pWi+l4IcIrGq3v+aUGcVigWPKh3TVcVyhYr/V5qt+zoSxH6LDvE2Z49UKsuaOSQFhHnKb91SZOncWGh7K01JumAoq4ADyjTfDFExTXE0HVecgwbEI7xlnyVgI/I4OfqPHHDdLk3TuaWpfoq1rLFCJQwMjE+jlm1++kZA=='
binary_signature_rsa_sha512 = b'OajQbB55E5B/heKbhcUaBvKiArrmYdfs4nJLU39rSk/3e5yvy9F9osnWAeJUu9xnThDnmBrvWSFeDnQIe2Y/hhypEHesdMsPG6R+RkFbQxv4icU+oEDh8wFetDEByuyueox/zqA+z6X9knt8+ufs6Mdfw0UIcxbg9rgNaB75JleI/ye9f97sAXc8K5lmZ6IHst200TX6Bw5Onpf2OLKOmsMdekLLdTmUew4ynNmeMlOdE20EUJvsH3y7WRBbW3JI8ffLBT4NHNyOfvt0CCOmynpmbEjfGg7jsq6J3bl4rZVrlDovMhuP3iyxjiwtj5gq44g++FYtYw8aQGXfBb28wA=='


def setUpModule():
    saml.init('/home/jordan/dev/saml/data/')
    global key, cert, transform_sha256, transform_sha512
    key = saml.key_read_file('/home/jordan/dev/saml/lua/t/data/sp.key', saml.KeyDataFormatPem)
    saml.key_add_cert_file(key, '/home/jordan/dev/saml/lua/t/data/sp.crt', saml.KeyDataFormatCertPem)
    cert = saml.key_read_file('/home/jordan/dev/saml/lua/t/data/sp.crt', saml.KeyDataFormatCertPem)

    transform_sha256 = saml.find_transform_by_href('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256')
    transform_sha512 = saml.find_transform_by_href('http://www.w3.org/2001/04/xmldsig-more#rsa-sha512')


class TestSignBinary(unittest.TestCase):

    def test_generates_correct_bytes_using_rsa_sha256(self):
      result = saml.sign_binary(key, transform_sha256, binary_data)
      self.assertEqual(binary_signature_rsa_sha256, b64encode(result))

    def test_generates_correct_bytes_using_rsa_sha512(self):
      result = saml.sign_binary(key, transform_sha512, binary_data)
      self.assertEqual(binary_signature_rsa_sha512, b64encode(result))


class TestSignXML(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open('/home/jordan/dev/saml/lua/t/data/simple-input.xml') as f:
            cls.input = f.read()

    def test_errors_for_invalid_document(self):
        with self.assertRaisesRegex(saml.error, 'unable to parse xml string'):
            saml.sign_xml(key, transform_sha256, 'plaintext')

    def test_errors_for_empty_document(self):
        with self.assertRaisesRegex(saml.error, 'unable to parse xml string'):
            saml.sign_xml(key, transform_sha256, '<?xml version="1.0" encoding="UTF-8"?>')

    def test_errors_for_document_with_no_id_attr(self):
        with self.assertRaisesRegex(saml.error, 'saml sign failed'):
            saml.sign_xml(key, transform_sha256, '<?xml version="1.0" encoding="UTF-8"?><Envelope xmlns="urn:envelope"></Envelope>', id_attr='ID')

    def test_generates_correct_document_using_rsa_sha256(self):
        with open('/home/jordan/dev/saml/lua/t/data/simple-signed-rsa-sha256.xml') as f:
            expected = f.read()
            result = saml.sign_xml(key, transform_sha256, self.input)
            self.assertEqual(expected, result)


class TestVerifyBinary(unittest.TestCase):

    def test_rejects_incorrectly_signed_content(self):
        valid = saml.verify_binary(cert, transform_sha256, binary_data, "bogus signature")
        self.assertFalse(valid)

    def test_verifies_correctly_signed_content_using_rsa_sha256(self):
        valid = saml.verify_binary(cert, transform_sha256, binary_data, b64decode(binary_signature_rsa_sha256))
        self.assertTrue(valid)

    def test_verifies_correctly_signed_content_using_rsa_sha512(self):
        valid = saml.verify_binary(cert, transform_sha512, binary_data, b64decode(binary_signature_rsa_sha512))
        self.assertTrue(valid)


class TestVerifyDoc(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.mngr = saml.create_keys_manager([ cert ])

    def test_rejects_an_incorrectly_signed_document(self):
        doc = saml.doc_read_file("/home/jordan/dev/saml/lua/t/data/simple-bad-sig-rsa-sha256.xml")
        valid = saml.verify_doc(self.mngr, doc)
        self.assertFalse(valid)

    def test_verifies_a_correctly_signed_document(self):
        doc = saml.doc_read_file("/home/jordan/dev/saml/lua/t/data/simple-signed-rsa-sha256.xml")
        valid = saml.verify_doc(self.mngr, doc)
        self.assertTrue(valid)
