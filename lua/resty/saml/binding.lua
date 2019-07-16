--[[---
Functions for creating or parsing SAML bindings
@module resty.saml.binding
]]

local saml = require "saml"

local _M = {}

--[[---
Create a redirect binding
@tparam xmlSecKey* key
@tparam table params
@treturn ?string signature
@treturn ?string error
@see saml.sign_binary
]]
function _M.create_redirect(key, params)
  local saml_type
  if params.SAMLRequest then
    saml_type = "SAMLRequest"
  elseif params.SAMLResponse then
    saml_type = "SAMLResponse"
  end
  assert(saml_type, "no saml request or response")

  return saml.binding_redirect_create(key, saml_type, params[saml_type], params.SigAlg, params.RelayState)
end

--[[---
Parse a redirect binding
@tparam string saml_type either SAMLRequest or SAMLResponse
@tparam func cert_from_doc determine the signing public key from the document
@treturn ?xmlDoc* doc
@treturn ?table args
@treturn ?string error
@see saml.verify_binary
]]
function _M.parse_redirect(saml_type, cert_from_doc)
  if ngx.req.get_method() ~= "GET" then return nil, nil, "method not allowed" end
  local args = ngx.req.get_uri_args()
  local doc, err = saml.binding_redirect_parse(saml_type, args, cert_from_doc)
  return doc, args, err
end

--[[---
Create a post binding
@tparam xmlSecKey* key
@tparam string saml_type
@tparam string content
@tparam string sig_alg
@tparam string relay_state
@tparam string destination
@treturn ?string html
@treturn ?string error
@see saml.sign_xml
]]
function _M.create_post(key, saml_type, content, sig_alg, relay_state, destination)
  return saml.binding_post_create(key, saml_type, content, sig_alg, relay_state, destination)
end

--[[---
Parse a post binding
@tparam string saml_type either SAMLRequest or SAMLResponse
@tparam func key_mngr_from_doc determine the signing public key from the document
@treturn ?xmlDoc* doc
@treturn ?table args
@treturn ?string error
@see saml.verify_doc
]]
function _M.parse_post(saml_type, key_mngr_from_doc)
  if ngx.req.get_method() ~= "POST" then return nil, nil, "method not allowed" end

  ngx.req.read_body()
  local args, err = ngx.req.get_post_args()
  if not args then return nil, nil, err end

  if not args[saml_type] then return nil, args, "no " .. saml_type end
  local doc, err = saml.binding_post_parse(args[saml_type], key_mngr_from_doc)
  return doc, args, err
end

return _M
