from base64 import b64decode, b64encode
import os
import unittest

import saml

key = None
cert = None
transform_sha512 = None
authn_request = None
TEST_DATA_DIR = os.getenv('TEST_DATA_DIR')

redirect_binding = 'SAMLRequest=fVNNr9MwELz3V1i%2BN3Hy%2BkGtNqi0fFQqbdQEDlyQsTfUUmwH23mv%2FHuc0KIgQU6W7JnZmd312jFVN3Tb%2Bqu%2BwI8WnEc3VWtH%2B4cNbq2mhjnpqGYKHPWcFtuPR5pGhDbWeMNNjQeUcQZzDqyXRmN02G%2Fw%2BfT2eH5%2FOH19RVZLsqwIeSJsLghZpISvxEpUq2W1SJesgpXgPJ1h9BmsC%2FwNDnIY5dY8SwH2FCptcJEjHwIEbedaOGjnmfYBSZLZlCynyaJMn%2Bg8pbP5F4z2ASk1873Y1fuGxrEUTQQ3ppoaIm5UXBTnAuyz5BA116Yv1wd%2BI7WQ%2Bvt41m%2B%2FQY5%2BKMt8mp%2BLEqPtI%2F%2FOaNcqsHf5T5fjHxPubw8ClEnioAW3zsRrxh3OJgitu27TPqnNxqgKPBPMs469joesh0pDu%2F4d9rmpJf%2BJ3hmrmP9%2FuCRK%2BhspplUPpaCYrLdCWHAuhKxr87KzwHyYibct4HhQ6r5lIPqdC33wcPNoZ1TDrHTdMEIE7vuMj5RD6K4OS3SBKhvdM055hwvXeThejBXd7ICHuqVl2jXG%2Bnsz%2Fine%2BY1HDGeTx%2FPw62STXw%3D%3D&RelayState=%2F&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha512&Signature=k0%2BbynPfqT5eg6QqV5nJ0sK6%2Bxun8kMkaUJY4a1BtgF7Y8PJgxghPLFt2EaSeQKsNGnkWW1j7ex2iudWZgX0UkpHiZwyro6l45OMkTBL5CIwaO1jvQIzhIlJkOIw1c8jE0Wpy5M8Rf4GOxl94YOgfbF%2F8JvJgU8OJxk1CW1OFgU8ds9ZhjXaXsAOSFZ6Cg5GozkCprjwbL0TjdgVNXwb6hFMQo1DGsoScIdX64orHC4pjhkdayT2zT9Hnm3S98pM8T3G1G3wCivGYiomRWRGvEE3vm4GkeRplaG%2FqbZwyFyY5yNhqhTkfHDi59249G26mKYp8auOm9onfNSyTXkhtg%3D%3D'


def cb_none(doc):
    return None

def cb_cert(doc):
    return cert

def cb_mngr(doc):
    return mngr


def setUpModule():
    saml.init(os.getenv('DATA_DIR'))
    global key, cert, transform_sha512, authn_request

    key = saml.key_read_file(TEST_DATA_DIR + 'sp.key', saml.KeyDataFormatPem)
    saml.key_add_cert_file(key, TEST_DATA_DIR + 'sp.crt', saml.KeyDataFormatCertPem)
    cert = saml.key_read_file(TEST_DATA_DIR + 'sp.crt', saml.KeyDataFormatCertPem)

    transform_sha512 = saml.find_transform_by_href('http://www.w3.org/2001/04/xmldsig-more#rsa-sha512')

    with open(TEST_DATA_DIR + 'authn_request.xml') as f:
        authn_request = f.read()


class TestCreateRedirect(unittest.TestCase):

    def test_errors_for_bad_sig_alg(self):
        with self.assertRaisesRegex(saml.error, 'invalid signature algorithm'):
            saml.binding_redirect_create(key, 'SAMLRequest', authn_request, '/', 'alg')

    def test_creates_a_full_query_string(self):
        query_string = saml.binding_redirect_create(key, 'SAMLRequest', authn_request, 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512', '/')
        self.assertEqual(redirect_binding, query_string)


class TestParseRedirect(unittest.TestCase):

    def setUp(self):
        self.valid_args = {
            'SAMLRequest': 'nZLPT8IwFIDv/BVN72NjER0vMIIQIwnqAtODtzqqNOna2feG8t/bTSAkEg7emr4f3/deOxx/l5ptpUNlzYj3uhFn47QzRFHqCiY1bcxSftYSiflEg9AERrx2BqxAhWBEKRGogNXkYQFxNwKBKB35dvykpLpcUzlLtrCas5eDStyozGcjrtZB0hwRazk3SMKQj0a9QRBdB/FNHvegH8FV/5WzmfdURlDbYENUQRhqWwi9sUiQRMkgRLScZXvcrTJrZT4uu739JiHc53kWZE+rnLPJYcapNViX0q2k26pCPi8X58FJKApswVu1lu7RU0Z86XV3bF96jPG0w1j7ANDO7NiddaWgy5bNjd/Ue5sK0pCiHU/PqgzDk+ZHWAWN1HyWWa2K3T+Y5IRB5cl+PVrbr6mTgvyU5GrJQ/+nwr+fKv0B',
            'RelayState': '/',
            'SigAlg': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
            'Signature': 'i+YCidTVfm/Sza2nkBEx+489RWiEI56SV/XJRC9d1hK0dFh9slDZsW7ZBJqSMyQ8CH/noHR46qjTjK5QBPH6awCxRieUFrJQ/ePy6f14cZfPgJxE7ctb8qwNgb6xkqGU2ou/7Bui8DH+mrAKaiJWSpO9AYKteBvGW0zeFBqbQh6M912Hz9m+SjW+l1bTif4LxOn+zDtNrW+QQmCCakcPUOOQhaB+Ml1RaEfu6NVTvCdrwA/1BWfpTb7XyBDvu3GXe4DPmuu0kGqUkUyWhLfFJ3oUNIgUlhXSj6gBP8Hus4ooTbQGNdfiNxBq2SHBdJVN3fVFFA1d+I5MOLlgemGm4g==',
        }

    def test_errors_for_non_GET_method(self):
        pass

    def test_errors_for_bad_base64_encoding(self):
        self.valid_args['SAMLRequest'] = 'xml'
        doc = None
        with self.assertRaisesRegex(saml.error, 'invalid base64 content'):
            doc = saml.binding_redirect_parse('SAMLRequest', self.valid_args, cb_none)
        self.assertIsNone(doc)

    def test_errors_for_bad_compression(self):
        self.valid_args['SAMLRequest'] = b64encode('xml'.encode('utf8'))
        doc = None
        with self.assertRaisesRegex(saml.error, 'data not in zlib format'):
            doc = saml.binding_redirect_parse('SAMLRequest', self.valid_args, cb_none)
        self.assertIsNone(doc)

    def test_errors_for_invalid_xml(self):
        self.valid_args['SAMLRequest'] = 'q8jN4QIA'
        doc = None
        with self.assertRaisesRegex(saml.error, 'content is not valid xml'):
            doc = saml.binding_redirect_parse('SAMLRequest', self.valid_args, cb_none)
        self.assertIsNone(doc)

    def test_errors_for_invalid_document(self):
        self.valid_args['SAMLRequest'] = 'fVNNj9MwEL33V1i+N2nKLkhWG1S6QlRa2KjJ7oGbsWeppfgDz2S3/Hsc06IgQU62xu/NvDcz3qC0fRC7gU7uCD8GQGJn2zsU+WHLh+iEl2hQOGkBBSnR7j7fi3WxEiF68sr3fEKZZ0hEiGS84+wJIqbLlqc4Z030L0ZD/JIoW942jJISzg6IAxwcknSUkKvqZrl6t6zedus34nYtbm6/cnaXkMZJyslOREGUpdGhgLO0oYdCeVu27UML8cUoKMIp5HJZ+QfjtHHf50V/+w1C8anrmmXz0Hac7a5G9t7hYCFe0j8e7/+IwL81aLC+KlMuOI8i3kuFvF4wthnbJrLTWM9RLZDUkuTI3pRT1jVLEGP/DneN7436yT76aCX931xVVDli9PI5QwVYafqd1hEQk8m+96/7CJLSTCgOwMtJqcu6gM7Lk/pAcCa29zbIaHAcRrKgKHu8upxC933ahiM817MLo4QacSncpOPVRz3ODlSq20XpMPhIl2b8M/mot5wRXC+uz9M/UC9+AQ=='
        doc = None
        with self.assertRaisesRegex(saml.error, 'document does not validate against schema'):
            doc = saml.binding_redirect_parse('SAMLRequest', self.valid_args, cb_none)
        self.assertIsNotNone(doc)

    def test_errors_when_no_cert_is_found(self):
        doc = None
        with self.assertRaisesRegex(saml.error, 'no cert'):
            doc = saml.binding_redirect_parse('SAMLRequest', self.valid_args, cb_none)
        self.assertIsNotNone(doc)

    def test_errors_for_invalid_signature(self):
        self.valid_args['Signature'] = 'sig'
        doc = None
        with self.assertRaisesRegex(saml.error, 'invalid base64 content'):
            doc = saml.binding_redirect_parse('SAMLRequest', self.valid_args, cb_cert)
        self.assertIsNotNone(doc)

    def test_errors_for_verify_failure(self):
        self.valid_args['Signature'] = 'c2lnCG=='
        doc = None
        with self.assertRaisesRegex(saml.error, 'signature does not match'):
            doc = saml.binding_redirect_parse('SAMLRequest', self.valid_args, cb_cert)
        self.assertIsNotNone(doc)

    def test_returns_the_parsed_document(self):
        doc = saml.binding_redirect_parse('SAMLRequest', self.valid_args, cb_cert)
        self.assertEqual('id-80', saml.doc_id(doc))
