local binding   = require "resty.saml.binding"
local constants = require "resty.saml.constants"
local sig       = require "resty.saml.sig"
local templates = require "templates"
local xml       = require "resty.saml.xml"

local _M = {}
local mt = { __index = _M }


function _M:new(metadata)
  local sp = {}
  local err = ""
  sp.key = sig.load_key_file(metadata.key_file)
  sp.cert = sig.load_cert_file(metadata.cert_file)
  sig.key_load_cert_file(sp.key, metadata.cert_file)

  sp.idp_cert = sig.load_cert_file(metadata.idp.cert_file)
  sp.idp_mngr, err = sig.create_keys_manager({ sp.idp_cert })
  assert(sp.idp_mngr, err)

  sp.metadata = metadata
  return setmetatable(sp, mt)
end

function _M:metadata_xml()
  local str = templates.metadata(self.metadata)
  local body, err = sig.sign_xml(self.key, constants.SIGNATURE_ALGORITHMS.RSA_SHA512, str)
  if err then
    ngx.log(ngx.ERR, err)
    ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
  end

  ngx.header.content_type = "application/xml"
  ngx.header.content_length = #body
  ngx.say(body)
  ngx.exit(ngx.HTTP_OK)
end

function _M:authn_request()
  return templates.authn_request({
    uuid="dbb9fe26-6950-11e9-881e-0242ac140002",
    datetime="2019-04-28T00:59:21Z",
    issuer=self.metadata.entity_id,
    destination="http://localhost:8089/sso",
    acs_url=self.metadata.entity_id .. self.metadata.acs.location,
    name="OpenResty Service Provider",
  })
end

function _M:sso(relay_state)
  if ngx.req.get_method() ~= "GET" then
    ngx.exit(ngx.HTTP_NOT_ALLOWED)
  end

  local req = self:authn_request()

  if self.metadata.sso.binding == constants.XMLNS.BINDINGS.HTTP_REDIRECT then
    local query_str, err = binding.create_redirect(self.key, constants.SIGNATURE_ALGORITHMS.RSA_SHA512, req, relay_state)
    if err then
      ngx.log(ngx.ERR, err)
      ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    ngx.status = ngx.HTTP_MOVED_TEMPORARILY
    ngx.header.cache_control = "no-cache, no-store"
    ngx.header.pragma = "no-cache"
    ngx.header.location = "http://localhost:8089/sso?" .. query_str
  elseif self.metadata.sso.binding == constants.XMLNS.BINDINGS.HTTP_POST then
    local body, err = binding.create_post(self.key, constants.SIGNATURE_ALGORITHMS.RSA_SHA512, "http://localhost:8089/sso", {
      SAMLRequest = req,
      RelayState = relay_state,
    })
    if err then
      ngx.log(ngx.ERR, err)
      ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
    ngx.header.cache_control = "no-cache, no-store"
    ngx.header.pragma = "no-cache"
    ngx.header.content_type = "text/html"
    ngx.header.content_length = #body
    ngx.say(body)
  else
    ngx.log(ngx.ERR, "unknown binding " .. self.metadata.sso.binding)
    ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
  end
  ngx.exit(ngx.HTTP_OK)
end

function _M:acs()
  if ngx.req.get_method() ~= "POST" then
    ngx.exit(ngx.HTTP_NOT_ALLOWED)
  end

  ngx.req.read_body()
  local args, err = ngx.req.get_post_args()
  if not args then
    ngx.log(ngx.ERR, "failed to get post args: " .. err)
    ngx.exit(ngx.HTTP_BAD_REQUEST)
  end

  if not args.SAMLResponse then
    ngx.exit(ngx.HTTP_BAD_REQUEST)
  end

  local doc = xml.parse(ngx.decode_base64(args.SAMLResponse))
  if doc == nil then
    return nil, args, "unable to parse file"
  end

  local valid, err = sig.verify_doc(self.idp_mngr, doc)
  if err then
    xml.free(doc)
    ngx.log(ngx.ERR, err)
    ngx.exit(ngx.HTTP_BAD_REQUEST)
  end

  if not valid then
    xml.free(doc)
    ngx.log(ngx.WARN, "invalid signature")
    ngx.exit(ngx.HTTP_BAD_REQUEST)
  end

  return doc, args, nil
end

return _M
