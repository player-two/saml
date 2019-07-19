local saml  = require "resty.saml"
local utils = require "utils"

local _M = {}

local RSA_SHA_512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"

local SIGNING_KEY = assert(saml.key_read_file("/ssl/idp.key", saml.KeyDataFormatPem))
local SIGNING_CERT = assert(saml.key_read_file("/ssl/idp.crt", saml.KeyDataFormatCertPem))
if not saml.key_add_cert_file(SIGNING_KEY, "/ssl/idp.crt", saml.KeyDataFormatCertPem) then
  assert(nil, "could not add cert to signing key")
end

local SP_CERT = assert(saml.key_read_file("/ssl/sp.crt", saml.KeyDataFormatCertPem))

local SP_URI = "http://localhost:8088"
local IDP_URI = "http://localhost:8089"

local function cert_from_doc(doc)
  local issuer = saml.doc_issuer(doc)
  if issuer == SP_URI then
    return SP_CERT
  else
    ngx.log(ngx.WARN, "issuer " .. tostring(issuer) .. " not recognized")
    return nil
  end
end

local RESPONSE = [[
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${uuid}" Version="2.0" IssueInstant="${issue_instant}" Destination="${destination}" InResponseTo="${in_response_to}">
  <saml:Issuer>${issuer}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="${status}"/>
  </samlp:Status>
  <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="assertion-${uuid}" Version="2.0" IssueInstant="${issue_instant}">
    <saml:Issuer>${issuer}</saml:Issuer>
    <saml:Subject>
      <saml:NameID SPNameQualifier="${destination}" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">${name_id}</saml:NameID>
    </saml:Subject>
    <saml:AuthnStatement AuthnInstant="${issue_instant}" SessionIndex="${session_index}">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="username" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">world</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
]]

local function response(destination, in_response_to, status)
  return utils.interp(RESPONSE, {
    destination = destination,
    in_response_to = in_response_to,
    issue_instant = os.date("!%Y-%m-%dT%TZ"),
    issuer = IDP_URI,
    name_id = "id-" .. math.random(1, 100),
    session_index = "id-" .. math.random(1, 100),
    status = status,
    uuid = "id-" .. math.random(1, 100),
  })
end

local LOGOUT_RESPONSE = [[
<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${uuid}" Version="2.0" IssueInstant="${issue_instant}" Destination="${destination}" InResponseTo="${in_response_to}">
  <saml:Issuer>${issuer}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="${status}"/>
  </samlp:Status>
</samlp:LogoutResponse>
]]

local function logout_response(destination, in_response_to, status)
  return utils.interp(LOGOUT_RESPONSE, {
    destination = destination,
    in_response_to = in_response_to,
    issue_instant = os.date("!%Y-%m-%dT%TZ"),
    issuer = IDP_URI,
    status = status,
    uuid = "id-" .. math.random(1, 100),
  })
end

function _M:sso(relay_state)
  local doc, args, err = saml.binding.parse_redirect("SAMLRequest", cert_from_doc)

  local request_id = ""
  if doc then
    request_id = saml.doc_id(doc)
    saml.doc_free(doc)
  end

  local status
  if err then
    ngx.log(ngx.WARN, err)
    status = saml.STATUS_REQUESTER
  else
    status = saml.STATUS_SUCCESS
  end

  local dest = SP_URI .. "/acs"

  local body, err = saml.binding.create_post(SIGNING_KEY, "SAMLResponse", response(dest, request_id, status), RSA_SHA_512, args.RelayState, dest)
  if err then
    ngx.log(ngx.ERR, err)
    ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
  end

  ngx.header.cache_control = "no-cache, no-store"
  ngx.header.pragma = "no-cache"
  ngx.header.content_type = "text/html"
  ngx.header.content_length = #body
  ngx.say(body)
  ngx.exit(ngx.HTTP_OK)
end

function _M:sls(relay_state)
  local doc, args, err = saml.binding.parse_redirect("SAMLRequest", cert_from_doc)

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

  local dest = SP_URI .. "/sls"

  local body, err = saml.binding.create_post(SIGNING_KEY, "SAMLResponse", logout_response(dest, request_id, status), RSA_SHA_512, args.RelayState, dest)
  if err then
    ngx.log(ngx.ERR, err)
    ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
  end

  ngx.header.cache_control = "no-cache, no-store"
  ngx.header.pragma = "no-cache"
  ngx.header.content_type = "text/html"
  ngx.header.content_length = #body
  ngx.say(body)
  ngx.exit(ngx.HTTP_OK)
end

return _M
