local ffi = require "ffi"

local binding   = require "resty.saml.binding"
local constants = require "resty.saml.constants"
local sig       = require "resty.saml.sig"
local templates = require "templates"
local xml       = require "resty.saml.xml"

local _M = {}
local mt = { __index = _M }


function _M:new(metadata)
  local idp = {}
  local err = ""
  idp.key = sig.load_key_file(metadata.key_file)
  idp.cert = sig.load_cert_file(metadata.cert_file)
  idp.mngr, err = sig.create_keys_manager({ self.cert })
  assert(idp.mngr, err)
  idp.metadata = metadata
  idp.service_providers = {}
  return setmetatable(idp, mt)
end

function _M:register_service_provider(sp)
  sp.mngr, err = sig.create_keys_manager({ sp.cert })
  assert(sp.mngr, err)
  self.service_providers[sp.entity_id] = sp
end

function _M:metadata_xml()
  local xml = templates.metadata(self.metadata)
  local body, err = sig.sign_xml(self.key, constants.SIGNATURE_ALGORITHMS.RSA_SHA512, xml)
  if err then
    ngx.log(ngx.ERR, err)
    ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
  end

  ngx.header.content_type = "application/xml"
  ngx.header.content_length = #body
  ngx.say(body)
  ngx.exit(ngx.HTTP_OK)
end

function _M:sso(relay_state)
  local args, doc, sp, err
  local function cert_from_doc(doc)
    local issuer = xml.issuer(doc)
    if not issuer then return nil, "no issuer" end

    sp = self.service_providers[issuer]
    if not sp then return nil, "service provider for " .. issuer .. " not found" end
    return sp.cert, nil
  end

  if ngx.req.get_method() == "GET" then
    args = ngx.req.get_uri_args()
    if not args.SAMLRequest then return nil, nil, "No SAMLRequest" end
    if not args.SigAlg then return nil, nil, "No SigAlg" end
    doc, err = binding.parse_redirect(args.SigAlg, args.SAMLRequest, args.RelayState, args.Signature, cert_from_doc)
  elseif ngx.req.get_method() == "POST" then
    ngx.req.read_body()
    args, err = ngx.req.get_post_args()
    if not err then
      doc, err = binding.parse_post(args.SAMLRequest, cert_from_doc)
    end
  else
    ngx.exit(ngx.HTTP_NOT_ALLOWED)
  end

  xml.free(doc)
  if err then
    ngx.log(ngx.ERR, err)
    ngx.exit(ngx.HTTP_BAD_REQUEST)
  end

  local dest = sp.entity_id .. sp.acs.location
  local relay_state = (args.RelayState or "")
  local resp = templates.response({
    destination = dest,
    issuer = self.metadata.entity_id,
  })
  if sp.acs.binding == constants.XMLNS.BINDINGS.HTTP_REDIRECT then
    local query_str, err = binding.create_redirect(self.key, constants.SIGNATURE_ALGORITHMS.RSA_SHA512, resp, relay_state)
    if err then
      ngx.log(ngx.ERR, err)
      ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
    ngx.status = ngx.HTTP_MOVED_TEMPORARILY
    ngx.header.cache_control = "no-cache, no-store"
    ngx.header.pragma = "no-cache"
    ngx.header.location = dest .. "?" .. query_str
  elseif sp.acs.binding == constants.XMLNS.BINDINGS.HTTP_POST then
    local body, err = binding.create_post(self.key, constants.SIGNATURE_ALGORITHMS.RSA_SHA512, dest, {
      SAMLResponse = resp,
      RelayState = relay_state
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
    ngx.log(ngx.ERR, "unknown binding " .. tostring(sp.acs.binding))
    ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
  end
end

return _M
