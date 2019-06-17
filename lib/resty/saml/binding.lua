--[[---
Functions for creating or parsing SAML bindings
]]

local saml = require "saml"
local zlib = require "zlib"

local _M = {}

local _WINDOW_BITS = -15


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

  local ok, deflated = pcall(zlib.deflate(zlib.DEFAULT_COMPRESSION, _WINDOW_BITS), params[saml_type], "finish")
  if not ok then return nil, saml_type .. " cannot be compressed" end
  local deflated_encoded = ngx.encode_base64(deflated)
  if not deflated_encoded then return nil, "decompressed " .. saml_type .. " cannot be base64 encoded" end

  local transform_id = saml.find_transform_by_href(params.SigAlg)
  if not transform_id then return nil, "signature algorithm not found" end

  local query_string = saml_type .. "=" .. ngx.escape_uri(deflated_encoded)
  if params.RelayState then
    query_string = query_string .. "&RelayState=" .. ngx.escape_uri(params.RelayState)
  end
  query_string = query_string .. "&SigAlg=" .. ngx.escape_uri(params.SigAlg)

  local signature, err = saml.sign_binary(key, transform_id, query_string)
  if err then return nil, err end
  return query_string .. "&Signature=" .. ngx.escape_uri(ngx.encode_base64(signature)), nil
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
  local encoded_deflated = args[saml_type]
  if not encoded_deflated then return nil, args, "no " .. saml_type end

  if not args.SigAlg then return nil, args, "no SigAlg" end
  local transform_id = saml.find_transform_by_href(args.SigAlg)
  if not transform_id then return nil, "signature algorithm not found" end

  if not args.Signature then return nil, args, "no Signature" end
  local signature = ngx.decode_base64(args.Signature)
  if not signature then return nil, args, "signature is not valid base64" end

  local deflated = ngx.decode_base64(encoded_deflated)
  if not deflated then return nil, args, saml_type .. " is not valid base64" end
  local ok, xml_str = pcall(zlib.inflate(_WINDOW_BITS), deflated)
  if not ok then return nil, args, saml_type .. " is not valid compresssion format" end

  local doc = saml.doc_read_memory(xml_str)
  if doc == nil then return nil, args, saml_type .. " is not valid xml" end

  local ok = saml.doc_validate(doc)
  if not ok then return doc, args, "document does not validate against schema" end

  local cert = cert_from_doc(doc)
  if not cert then return doc, args, "no cert" end

  local sig_input = saml_type .. "=" .. ngx.escape_uri(encoded_deflated)
  if args.RelayState then
    sig_input = sig_input .. "&RelayState=" .. ngx.escape_uri(args.RelayState)
  end
  sig_input = sig_input .. "&SigAlg=" .. ngx.escape_uri(args.SigAlg)

  local valid, err = saml.verify_binary(cert, transform_id, sig_input, signature)
  if err then return doc, args, err end
  if not valid then return doc, args, "invalid signature" end

  return doc, args, nil
end

--[[---
Create a post binding
@tparam xmlSecKey* key
@tparam xmlSecTransformId transform_id
@tparam string destination
@tparam table params
@treturn ?string html
@treturn ?string error
@see saml.sign_xml
]]
function _M.create_post(key, transform_id, destination, params)
  local xml_str = params.SAMLRequest or params.SAMLResponse
  assert(xml_str, "no saml request or response")
  local signed, err = saml.sign_xml(key, transform_id, xml_str, {
    id_attr = "ID",
    insert_after = { saml.XMLNS_ASSERTION, "Issuer" },
  })
  if err then return nil, err end
  local encoded = ngx.encode_base64(signed)

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

  local encoded = args[saml_type]
  if not encoded then return nil, args, "no " .. saml_type end

  local content = ngx.decode_base64(encoded)
  if not content then return nil, args, saml_type .. " is not valid base64" end

  local doc = saml.doc_read_memory(content)
  if doc == nil then return nil, args, saml_type .. " is not valid xml" end

  local ok = saml.doc_validate(doc)
  if not ok then return doc, args, "document does not validate against schema" end

  local mngr = key_mngr_from_doc(doc)
  if not mngr then return doc, args, "no key manager" end

  local valid, err = saml.verify_doc(mngr, doc)
  if err then return doc, args, err end
  if not valid then return doc, args, "invalid signature" end

  return doc, args, nil
end

return _M
