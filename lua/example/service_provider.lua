local saml  = require "resty.saml"
local utils = require "utils"

local _M = {}

local RSA_SHA_512_HREF = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"

local SIGNING_KEY = assert(saml.key_read_file("/ssl/sp.key", saml.KeyDataFormatPem))
local SIGNING_CERT = assert(saml.key_read_file("/ssl/sp.crt", saml.KeyDataFormatCertPem))
if not saml.key_add_cert_file(SIGNING_KEY, "/ssl/sp.crt", saml.KeyDataFormatCertPem) then
  assert(nil, "could not add cert to signing key")
end

local IDP_CERT = assert(saml.key_read_file("/ssl/idp.crt", saml.KeyDataFormatCertPem))
local IDP_CERT_MNGR = assert(saml.create_keys_manager({ IDP_CERT }))

local SP_URI = "http://localhost:8088"
local IDP_URI = "http://localhost:8089"
local SP_PROVIDER_NAME = "Resty Service Provider"

local function key_mngr_from_doc(doc)
  local issuer = saml.doc_issuer(doc)
  if issuer == IDP_URI then
    return IDP_CERT_MNGR
  else
    ngx.log(ngx.WARN, "issuer " .. tostring(issuer) .. " not recognized")
    return nil
  end
end

local AUTHN_REQUEST = [[
<?xml version="1.0" ?>
<samlp:AuthnRequest xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" ID="${uuid}" IssueInstant="${issue_instant}" Destination="${destination}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="${acs_url}" ProviderName="${provider_name}">
  <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">${issuer}</saml:Issuer>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" AllowCreate="true"/>
</samlp:AuthnRequest>
]]

local function authn_request()
  return utils.interp(AUTHN_REQUEST, {
    acs_url = SP_URI .. "/acs",
    destination = IDP_URI .. "/sso",
    issue_instant = os.date("!%Y-%m-%dT%TZ"),
    issuer = SP_URI,
    provider_name = SP_PROVIDER_NAME,
    uuid = "id-" .. math.random(1, 100),
  })
end

local LOGOUT_REQUEST = [[
<?xml version="1.0"?>
<samlp:LogoutRequest xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0" ID="{* id *}" IssueInstant="{* issue_instant *}" Destination="{* destination *}">
  <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">{* issuer *}</saml:Issuer>
  <saml:NameID NameQualifier="{* name_qualifier *}" SPNameQualifier="{* sp_name_qualifier *}" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">{* name_id *}</saml:NameID>
  <samlp:SessionIndex>{* session_index *}</samlp:SessionIndex>
</samlp:LogoutRequest>
]]

local function logout_request(name_id, session_index)
  return utils.interp(LOGOUT_REQUEST, {
    destination = IDP_URI .. "/sls",
    name_id = name_id,
    name_qualifier = IDP_URI,
    id = "id-" .. math.random(1, 100),
    issue_instant = os.date("!%Y-%m-%dT%TZ"),
    issuer = SP_URI,
    provider_name = SP_PROVIDER_NAME,
    session_index = session_index,
    sp_name_qualifier = SP_URI,
  })
end

function _M.home()
  local username = ngx.var.cookie_username
  ngx.header.content_type = "text/html"
  if username then
    ngx.say("<h1>hello " .. username .. '</h1><a href="/logout">log out</a>')
  else
    ngx.say('<a href="/sso">log in</a>')
  end
  ngx.exit(ngx.HTTP_OK)
end

function _M.sso()
  if ngx.req.get_method() ~= "GET" then
    ngx.exit(ngx.HTTP_NOT_ALLOWED)
  end

  local args = ngx.req.get_uri_args()
  local relay_state = args.relay_state or "/"

  local query_str, err = saml.binding.create_redirect(SIGNING_KEY, {
    RelayState = relay_state,
    SAMLRequest = authn_request(),
    SigAlg = RSA_SHA_512_HREF,
  })
  if err then
    ngx.log(ngx.ERR, err)
    ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
  end


  ngx.status = ngx.HTTP_MOVED_TEMPORARILY
  ngx.header.cache_control = "no-cache, no-store"
  ngx.header.pragma = "no-cache"
  ngx.header.location = IDP_URI .. "/sso?" .. query_str
  ngx.exit(ngx.HTTP_OK)
end

function _M.acs()
  local doc, args, err = saml.binding.parse_post("SAMLResponse", key_mngr_from_doc)

  if err then
    if doc then saml.doc_free(doc) end
    ngx.log(ngx.WARN, err)
    ngx.exit(ngx.HTTP_BAD_REQUEST)
  end

  -- TODO: lookup status

  local attrs = saml.doc_attrs(doc)
  saml.doc_free(doc)

  ngx.header["Set-Cookie"] = "username=" .. attrs.username .. ";"

  local relay_state = "/"
  if args.relay_state then
    relay_state = ngx.unescape_uri(args.relay_state)
  end

  ngx.status = ngx.HTTP_MOVED_TEMPORARILY
  ngx.header.location = relay_state
  ngx.exit(ngx.HTTP_OK)
end

function _M.sls()
  local doc, args, err = saml.binding.parse_post("SAMLResponse", key_mngr_from_doc)

  local request_id = ""
  if doc then
    request_id = saml.doc_id(doc)
    saml.doc_free(doc)
  end

  local status
  if err then
    ngx.log(ngx.WARN, err)
    status = saml.STATUS_CODES_REQUESTER
  else
    status = saml.STATUS_CODES_SUCCESS
  end

  ngx.header["Set-Cookie"] = "username=; Max-Age=0"
  ngx.say(logout_response(request_id, saml.STATUS_CODES_SUCCESS))
  ngx.exit(ngx.HTTP_OK)
end

function _M.logout()
  local username = ngx.var.cookie_username
  if not username then
    ngx.exit(ngx.HTTP_UNAUTHORIZED)
  end

  local query_str, err = saml.binding.create_redirect(SIGNING_KEY, {
    RelayState =  "/",
    SAMLRequest = logout_request(name_id, session_index), -- TODO store these on ngx.shared during acs
    SigAlg = RSA_SHA_512_HREF,
  })
  if err then
    ngx.log(ngx.ERR, err)
    ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
  end

  ngx.status = ngx.HTTP_MOVED_TEMPORARILY
  ngx.header.cache_control = "no-cache, no-store"
  ngx.header.pragma = "no-cache"
  ngx.header.location = IDP_URI .. "/slo?" .. query_str
  ngx.exit(ngx.HTTP_OK)
end

return _M
