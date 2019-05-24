--[[---
Functions for creating or parsing SAML bindings
]]

local ffi = require "ffi"
local zlib = require "zlib"

local constants = require "resty.saml.constants"
local sig       = require "resty.saml.sig"
local xml       = require "resty.saml.xml"

local _M = {}

local function encode_uri(uri)
  local no_spaces = uri:gsub(" ", "+")
  return ngx.escape_uri(no_spaces)
end

local function decode_uri(encoded)
  local unescaped = ngx.unescape_uri(encoded)
  return unescaped:gsub(" ", "+")
end


local _FORM_INPUT = '<input type="hidden" name="${name}" value="${value}" />'
local _POST_FORM = [[
<!doctype html>
<html>
  <head>
    <title>Redirecting for Authentication...</title>
  </head>
  <body>
    <noscript>
      <p><strong>Note:</strong> Since your browser does not support JavaScript, you must press the Continue button once to proceed.</p>
    </noscript>
    <form id="login-form" action="${action}" method="POST">
    ${inputs}
    <noscript><input type="submit" value="Continue" /></noscript>
    </form>
    <script type="text/javascript">
      document.getElementById('login-form').submit();
    </script>
  </body>
</html>
]]

local function interp(s, tab)
  return s:gsub('($%b{})', function(w)
    local key = w:sub(3, -2)
    if not key:find(".", 2, true) then
      return tab[key] or ""
    else
      local t = tab
      for k in key:gmatch("%a+") do
        t = t[k]
        if not t then return "" end
      end
      return t
    end
  end)
end

local function post_form(action, params)
  local inputs = ""
  for k, v in pairs(params) do
    inputs = inputs .. interp(_FORM_INPUT, { name = k, value = v })
  end
  return interp(_POST_FORM, {
    action = action,
    inputs = inputs,
  })
end


--[[---
Create a redirect binding
@tparam xmlSecKeyPtr key
@tparam string sig_alg
@tparam string req
@tparam string relay_state
@treturn ?string signature
@treturn ?string error
@see sig.sign_binary
@see constants:SIGNATURE_ALGORITHMS
]]
function _M.create_redirect(key, sig_alg, req, relay_state)
  local deflated, _, _, _ = zlib.deflate()(ngx.encode_base64(req), "finish")
  local encoded = ngx.encode_base64(assert(deflated))

  local query_string = string.format("SAMLRequest=%s&RelayState=%s&SigAlg=%s",
    encode_uri(encoded),
    encode_uri(relay_state),
    encode_uri(ffi.string(assert(sig_alg)))
  )
  local signature, err = sig.sign_binary(key, sig_alg, query_string)
  if err then return nil, err end
  return query_string .. "&Signature=" .. encode_uri(ngx.encode_base64(signature)), nil
end

--[[---
Parse a redirect binding
@tparam string sig_alg
@tparam string deflated_encoded
@tparam string relay_state
@tparam string signature
@tparam func cert_from_doc determine the signing public key from the document
@treturn ?xmlDocPtr doc
@treturn ?string error
@see sig.verify_binary
@see constants:SIGNATURE_ALGORITHMS
]]
function _M.parse_redirect(sig_alg, deflated_encoded, relay_state, signature, cert_from_doc)
  local inflated, _, _, _ = zlib.inflate()(ngx.decode_base64(deflated_encoded))
  local req = ngx.decode_base64(assert(inflated))
  local doc = xml.parse(req)
  if doc == nil then return nil, "unable to read xml" end

  local err = xml.validate_doc(doc)
  if err then return doc, err end

  local cert = cert_from_doc(doc)
  if not cert then return doc, "no cert" end

  local sig_input = string.format("SAMLRequest=%s&RelayState=%s&SigAlg=%s",
    ngx.escape_uri(deflated_encoded),
    ngx.escape_uri(relay_state),
    ngx.escape_uri(sig_alg)
  )

  local valid, err = sig.verify_binary(cert, sig_alg, sig_input, ngx.decode_base64(signature))
  if err then return doc, err end
  if not valid then return doc, "invalid signature" end

  return doc, nil
end

--[[---
Create a post binding
@tparam xmlSecKeyPtr key
@tparam string sig_alg
@tparam string destination
@tparam table params
@treturn ?string html
@treturn ?string error
@see sig.sign_xml
]]
function _M.create_post(key, sig_alg, destination, params)
  local xml_str = params.SAMLRequest or params.SAMLResponse
  assert(xml_str, "no saml request or response")
  local req, err = sig.sign_xml(key, sig_alg, xml_str)
  if err then return nil, err end
  local encoded = ngx.encode_base64(req)

  local copy = {}
  for k, v in pairs(params) do copy[k] = v end
  if copy.SAMLRequest then
    copy.SAMLRequest = encoded
  else
    copy.SAMLResponse = encoded
  end
  return post_form(destination, copy), nil
end

--[[---
Parse a post binding
@tparam string encoded
@tparam func cert_from_doc determine the signing public key from the document
@treturn ?xmlDocPtr doc
@treturn ?string error
@see sig.verify_doc
]]
function _M.parse_post(encoded, cert_from_doc)
  local req = ngx.decode_base64(encoded)
  local doc = xml.parse(req)
  if doc == nil then return nil, "unable to read xml" end

  local err = xml.validate_doc(doc)
  if err then return doc, err end

  local cert = cert_from_doc(doc)
  if not cert then return doc, "no cert" end

  local mngr, err = sig.create_keys_manager({ cert })
  if err then return doc, err end

  local valid, err = sig.verify_doc(mngr, doc)
  if err then return doc, err end
  if not valid then return doc, "invalid signature" end

  return doc, nil
end

return _M
