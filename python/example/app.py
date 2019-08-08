from datetime import datetime
from flask import Flask, make_response, redirect, request
from urllib.parse import unquote_plus
import uuid

import saml


RSA_SHA_512_HREF = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'

SIGNING_KEY = saml.key_read_file('/ssl/sp.key', saml.KeyDataFormatPem)
SIGNING_CERT = saml.key_read_file('/ssl/sp.crt', saml.KeyDataFormatCertPem)
saml.key_add_cert_file(SIGNING_KEY, '/ssl/sp.crt', saml.KeyDataFormatCertPem)

IDP_CERT = saml.key_read_file('/ssl/idp.crt', saml.KeyDataFormatCertPem)
IDP_CERT_MNGR = saml.create_keys_manager([ IDP_CERT ])

SP_URI = 'http://localhost:5000'
IDP_URI = 'http://localhost:8089'
SP_PROVIDER_NAME = 'Flask Service Provider'

AUTHN_REQUEST = '''
<?xml version="1.0" ?>
<samlp:AuthnRequest xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" ID="{uuid}" IssueInstant="{issue_instant}" Destination="{destination}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{acs_url}" ProviderName="{provider_name}">
  <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">{issuer}</saml:Issuer>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" AllowCreate="true"/>
</samlp:AuthnRequest>
'''

LOGOUT_REQUEST = '''
<?xml version="1.0"?>
<samlp:LogoutRequest xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" ID="{id}" IssueInstant="{issue_instant}" Destination="{destination}">
  <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">{issuer}</saml:Issuer>
  <saml:NameID NameQualifier="{name_qualifier}" SPNameQualifier="{sp_name_qualifier}" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">{name_id}</saml:NameID>
  <samlp:SessionIndex>{session_index}</samlp:SessionIndex>
</samlp:LogoutRequest>
'''

app = Flask(__name__)
session = {}


def key_mngr_from_doc(doc):
    issuer = saml.doc_issuer(doc)
    if issuer == IDP_URI:
        return IDP_CERT_MNGR
    else:
        ngx.log(ngx.WARN, f'issuer {issuer} not recognized')
        return None

def authn_request():
    return AUTHN_REQUEST.format(
        acs_url = SP_URI + '/acs',
        destination = IDP_URI + '/sso',
        issue_instant = datetime.utcnow().isoformat(),
        issuer = SP_URI,
        provider_name = SP_PROVIDER_NAME,
        uuid = 'id-' + uuid.uuid4()
    )

def logout_request(name_id, session_index):
    return LOGOUT_REQUEST.format(
        destination = IDP_URI + '/sls',
        name_id = name_id,
        name_qualifier = IDP_URI,
        id = 'id-' + uuid.uuid4(),
        issue_instant = datetime.utcnow().isoformat(),
        issuer = SP_URI,
        provider_name = SP_PROVIDER_NAME,
        session_index = session_index,
        sp_name_qualifier = SP_URI
    )

def redirect_no_cache(uri):
    res = redirect(uri)
    res.headers['cache-control'] = 'no-cache, no-store'
    res.headers['pragma'] = 'no-cache'
    return res


@app.route('/', methods['GET'])
def home():
    if 'username' in session:
        return f'<h1>hello {session["username"]}</h1><a href="/logout">log out</a>'
    else:
        return '<a href="/sso">log in</a>'


@app.route('/sso', methods['GET'])
def sso():
    relay_state = request.args.get('relay_state', ['/'])[0]
    query_str = saml.binding.create_redirect(SIGNING_KEY, {
        RelayState = relay_state,
        SAMLRequest = authn_request(),
        SigAlg = RSA_SHA_512_HREF,
    })
    return redirect_no_cache(f'{IDP_URI}/sso?{query_str}')


@app.route('/acs', methods['POST'])
def acs():
    saml_response = request.form.get('SAMLResponse', [None])[0]
    if not saml_response:
        return make_response('<h1>Bad Request</h1>', 400)

    try:
        doc = saml.binding.parse_post(saml_response, key_mngr_from_doc)
    except saml.error as e:
        print(e)
        return make_response('<h1>Bad Request</h1>', 400)

    status_code = saml.doc_status_code(doc)
    if status_code != saml.STATUS_SUCCESS:
        print(f'IdP returned non-success status: {status_code}')
        return make_response('<h1>Internal Server Error</h1>', 500)

    attrs = saml.doc_attrs(doc)
    session['username'] = attrs['username']
    session['name_id'] = saml.doc_name_id(doc)
    session['session_index'] = saml.doc_session_index(doc)

    relay_state = request.form.get('RelayState')
    return redirect(unquote_plus(relay_state) if relay_state else '/')


@app.route('/sls', methods['POST'])
def sls():
    saml_response = request.form.get('SAMLResponse', [None])[0]
    if not saml_response:
        return make_response('<h1>Bad Request</h1>', 400)

    try:
        doc = saml.binding.parse_post(saml_response, key_mngr_from_doc)
    except saml.error as e:
        print(e)
        return make_response('<h1>Bad Request</h1>', 400)

    name = saml.doc_root_name(doc)
    if name == 'LogoutRequest':
        session = {}
        return make_response(logout_response(saml.doc_id(doc), saml.STATUS_CODES_SUCCESS))
    elif name == 'LogoutResponse':
        res = redirect('/')
        res.headers['set-cookie'] = 'username=; max-age=0'
        return res
    else:
        return make_response('<h1>Bad Request</h1>', 400)


@app.route('/logout', methods['GET'])
def logout():
    if not session.get('username'):
        return make_response('<h1>Unauthorized</h1>', 401)

    session = {}

    query_str = saml.binding_create_redirect(SIGNING_KEY, {
        RelayState = '/',
        SAMLRequest = logout_request(session['name_id'], session['session_index']),
        SigAlg = RSA_SHA_512_HREF,
    })

    res = redirect_no_cache(f'{IDP_URI}/sls?{query_str}')
    res.headers['set-cookie'] = 'username=; max-age=0'
    return res
