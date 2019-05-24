--[[---
Functions for singing and verifying cryptographic signatures
]]

local ffi = require "ffi"

local constants = require "resty.saml.constants"
local xml       = require "resty.saml.internal.xml"
local xs        = require "resty.saml.internal.xmlsec"

local _M = {}
local initialized = false

local xml_generic_no_error = ffi.cast("xmlGenericErrorFunc", function(ctx, msg, ...) end)
local xml_structured_no_error = ffi.cast("xmlStructuredErrorFunc", function(ctx, err) end)


--[[---
Initialize the libxml2 parser and xmlsec
@tparam[opt={}] table options
@treturn ?string
@usage local err = sig.init({ debug = true })
]]
function _M.init(options)
  -- https://www.aleksey.com/xmlsec/api/xmlsec-notes-init-shutdown.html
  options = options or {
    debug = false,
    crypto_lib = "openssl",
  }

  xml.xmlInitParser()

  if xs.xmlSecInit() < 0 then
    return "xmlsec initialization failed"
  end

  if xs.xmlSecCheckVersionExt(1, 1, 28, xs.xmlSecCheckVersionABICompatible) ~= 1 then
    return "loaded xmlsec library version is not compatible"
  end

  xs.load_crypto(options.crypto_lib)
  if xs.xmlSecCryptoAppInit(nil) < 0 then
    return "xmlsec crypto app initialization failed"
  end

  if xs.xmlSecCryptoInit() < 0 then
    return "xmlsec app initialization failed"
  end

  if not options.debug then
    -- silences stderr
    xml.xmlSetGenericErrorFunc(nil, xml_generic_no_error)
    xml.xmlSetStructuredErrorFunc(nil, xml_structured_no_error)
    xs.xmlSecErrorsSetCallback(nil)
  end

  initialized = true
  return nil
end

--[[---
Deinitialize xmlsec
]]
function _M.shutdown()
  -- https://www.aleksey.com/xmlsec/api/xmlsec-notes-init-shutdown.html
  xs.xmlSecCryptoShutdown()
  xs.xmlSecCryptoAppShutdown()
  xs.xmlSecShutdown()
end

--[[---
Load a private key from memory
@string data private key data
@treturn xmlSecKeyPtr
]]
function _M.load_key(data)
  return xs.xmlSecCryptoAppKeyLoadMemory(data, #data, xs.xmlSecKeyDataFormatPem, nil, nil, nil)
end

--[[---
Load a private key from a file
@string file path to private key file
@treturn xmlSecKeyPtr
]]
function _M.load_key_file(file)
  return xs.xmlSecCryptoAppKeyLoad(file, xs.xmlSecKeyDataFormatPem, nil, nil, nil)
end

--[[---
Load a public key from memory
@string data public key data
@treturn xmlSecKeyPtr
]]
function _M.load_cert(data)
  return xs.xmlSecCryptoAppKeyLoadMemory(data, #data, xs.xmlSecKeyDataFormatCertPem, nil, nil, nil)
end

--[[---
Load a public key from a file
@string file path to public key file
@treturn xmlSecKeyPtr
]]
function _M.load_cert_file(file)
  return xs.xmlSecCryptoAppKeyLoad(file, xs.xmlSecKeyDataFormatCertPem, nil, nil, nil)
end

--[[---
Add a public key from memory to a private key
@tparam xmlSecKeyPtr key
@tparam string data public key data
@treturn bool success
]]
function _M.key_load_cert(key, data)
  return xs.xmlSecCryptoAppKeyCertLoadMemory(key, data, #data, xs.xmlSecKeyDataFormatPem) == 0
end

--[[---
Add a public key from a file to a private key
@tparam xmlSecKeyPtr key
@tparam string file path to public key data
@treturn bool success
]]
function _M.key_load_cert_file(key, file)
  return xs.xmlSecCryptoAppKeyCertLoad(key, file, xs.xmlSecKeyDataFormatPem) == 0
end

--[[---
Create a keys manager with zero or more keys
@tparam {xmlSecKeyPtr,...} keys
@treturn ?xmlSecKeysMngrPtr
@treturn ?string error
@usage
local cert = sig.load_cert_file("/path/to/cert.pem")
local mngr, err = sig.create_keys_manager({ cert })
]]
function _M.create_keys_manager(keys)
  local mngr = xs.xmlSecKeysMngrCreate()
  if mngr == nil then
    return nil, "create keys manager failed"
  end

  if xs.xmlSecCryptoAppDefaultKeysMngrInit(mngr) < 0 then
    return nil, "initialize keys manager failed"
  end

  for _, key in pairs(keys) do
    if xs.xmlSecCryptoAppDefaultKeysMngrAdoptKey(mngr, key) < 0 then
      return nil, "adopt key failed"
    end
  end

  return mngr, nil
end

local function add_id(doc, node, name)
  local attr = node[0].properties
  while attr ~= nil do
    if xml.xmlStrEqual(attr[0].name, name) == 1 then
      local value = xml.xmlNodeListGetString(doc, attr[0].children, 1)
      if value ~= nil then
        return xml.xmlAddID(nil, doc, value, attr)
      end
    end
    attr = attr[0].next
  end
end

--[[---
Sign an XML document (mutates the input)
@tparam xmlSecKeyPtr key
@tparam string sig_alg
@tparam xmlDocPtr doc
@tparam[opt={}] table options
@treturn ?string error
@see constants:SIGNATURE_ALGORITHMS
]]
function _M.sign_doc(key, sig_alg, doc, options)
  -- https://www.aleksey.com/xmlsec/api/xmlsec-notes-sign.html
  assert(initialized)

  options = options or {}

  local root = xml.xmlDocGetRootElement(doc)
  if root == nil then
    return "no root node"
  end

  local id = nil
  if options.id_attr then
    add_id(doc, root, options.id_attr)

    local id_ptr = xml.xmlGetProp(root, options.id_attr)
    if id_ptr == nil then
      return "no ID property on document root"
    end
    id = "#" .. ffi.string(id_ptr)
    xml.xmlFree(ffi.cast("void *", id_ptr))
  end

  local transform_id = xs.xmlSecTransformIdListFindByHref(xs.xmlSecTransformIdsGet(), sig_alg, 0xFFFF)
  if transform_id == nil then
    return "transform not found"
  end

  -- <dsig:Signature/>
  local sign_node = xs.xmlSecTmplSignatureCreate(doc, xs.xmlSecTransformExclC14NId, transform_id, nil)
  if sign_node == nil then
    return "create signature template failed"
  end

  if options.insert_after then
    local target = xs.xmlSecFindNode(root, options.insert_after[2], options.insert_after[1])
    if target == nil then
      return options.insert_after[1] .. ":" .. options.insert_after[2] .. " node not found"
    end

    if xml.xmlAddNextSibling(target, sign_node) == nil then
      return "adding signature node failed"
    end
  else
    xml.xmlAddChild(root, sign_node)
  end

  -- <dsig:Reference/>
  local ref_node = xs.xmlSecTmplSignatureAddReference(sign_node, xs.xmlSecTransformSha1Id, nil, id, nil)
  if ref_node == nil then
    return "add reference to signature template failed"
  end

  if xs.xmlSecTmplReferenceAddTransform(ref_node, xs.xmlSecTransformEnvelopedId) == nil then
    return "add enveloped transform to reference failed"
  end

  if xs.xmlSecTmplReferenceAddTransform(ref_node, xs.xmlSecTransformExclC14NId) == nil then
    return "add c14n transform to reference failed"
  end

  -- <dsig:KeyInfo/>
  local key_info_node = xs.xmlSecTmplSignatureEnsureKeyInfo(sign_node, nil)
  if key_info_node == nil then
    return "add key info to sign node failed"
  end
 
  -- <dsig:X509Data/>
  local x509_data_node = xs.xmlSecTmplKeyInfoAddX509Data(key_info_node)
  if x509_data_node == nil then
    return "add x509 data to node failed"
  end

  if xs.xmlSecTmplX509DataAddCertificate(x509_data_node) == nil then
    return "add x509 cert to node failed"
  end

  local sig_ctx = xs.xmlSecDSigCtxCreate(nil)
  if sig_ctx == nil then
    return "create signature context failed"
  end

  sig_ctx[0].signKey = key

  if xs.xmlSecDSigCtxSign(sig_ctx, sign_node) < 0 then
    xs.xmlSecDSigCtxDestroy(sig_ctx)
    return "sign failed"
  end

  local status = sig_ctx[0].status
  xs.xmlSecDSigCtxDestroy(sig_ctx)
  if status ~= xs.xmlSecDSigStatusSucceeded then
    return "sign failed"
  end
  return nil
end

--[[---
Sign an XML string
@tparam xmlSecKeyPtr key
@tparam string sig_alg
@tparam string str
@tparam[opt={}] table options
@treturn ?string signed xml
@treturn ?string error
@see sign_doc
@see constants:SIGNATURE_ALGORITHMS
]]
function _M.sign_xml(key, sig_alg, str, options)
  local doc = xml.xmlReadMemory(str, #str, "tmp.xml", nil, 0)
  if doc == nil then
    return nil, "unable to parse xml string"
  end

  local err = _M.sign_doc(key, sig_alg, doc, options)
  if err then
    xml.xmlFreeDoc(doc)
    return nil, err
  end

  local buf = ffi.new("xmlChar*[1]")
  local buf_len = ffi.new("int[1]")
  xml.xmlDocDumpMemory(doc, buf, buf_len)
  xml.xmlFreeDoc(doc)
  return ffi.string(buf[0], buf_len[0]), nil
end

--[[---
Calculate a signature for a string
@tparam xmlSecKeyPtr key
@tparam string sig_alg
@tparam string data
@treturn ?string signature
@treturn ?string error
@see constants:SIGNATURE_ALGORITHMS
]]
function _M.sign_binary(key, sig_alg, data)
  assert(initialized)

  local trans_ctx = xs.xmlSecTransformCtxCreate()
  if trans_ctx == nil then
    return nil, "transform ctx create failed"
  end

  if xs.xmlSecTransformCtxInitialize(trans_ctx) < 0 then
    xs.xmlSecTransformCtxDestroy(trans_ctx)
    return nil, "transform ctx initialize failed"
  end

  local transform_id = xs.xmlSecTransformIdListFindByHref(xs.xmlSecTransformIdsGet(), sig_alg, 0xFFFF)
  if transform_id == nil then
    xs.xmlSecTransformCtxDestroy(trans_ctx)
    return nil, "transform not found"
  end

  if xs.xmlSecPtrListAdd(trans_ctx[0].enabledTransforms, ffi.cast("void*", transform_id)) < 0 then
    xs.xmlSecTransformCtxDestroy(trans_ctx)
    return nil, "transform enable failed"
  end

  local trans = xs.xmlSecTransformCtxCreateAndAppend(trans_ctx, transform_id)
  if trans == nil then
    xs.xmlSecTransformCtxDestroy(trans_ctx)
    return nil, "transform add to context failed"
  end

  trans[0].operation = xs.xmlSecTransformOperationSign

  if xs.xmlSecTransformSetKey(trans, key) < 0 then
    xs.xmlSecTransformCtxDestroy(trans_ctx)
    return nil, "set key failed"
  end

  if xs.xmlSecTransformCtxBinaryExecute(trans_ctx, data, #data) < 0 then
    xs.xmlSecTransformCtxDestroy(trans_ctx)
    return nil, "signature execution failed"
  end

  if trans_ctx[0].status ~= xs.xmlSecTransformStatusFinished then
    xs.xmlSecTransformCtxDestroy(trans_ctx)
    return nil, "signature status unknown"
  end

  local signature = ffi.string(xs.xmlSecBufferGetData(trans_ctx[0].result), xs.xmlSecBufferGetSize(trans_ctx[0].result))
  xs.xmlSecTransformCtxDestroy(trans_ctx)
  return signature, nil
end

--[[---
Verify that a XML document has been signed with the key corresponding to a cert
@tparam xmlSecKeysMngrPtr mngr
@tparam xmlDocPtr doc
@tparam[opt={}] table options
@treturn bool valid
@treturn ?string error
]]
function _M.verify_doc(mngr, doc, options)
  -- https://www.aleksey.com/xmlsec/api/xmlsec-notes-verify.html
  assert(initialized)

  options = options or {}

  local root = xml.xmlDocGetRootElement(doc)
  if root == nil then
    return false, nil
  end

  if options.id_attr then
    add_id(doc, root, options.id_attr)
  end
  
  local node = xs.xmlSecFindNode(root, xs.xmlSecNodeSignature, xs.xmlSecDSigNs)
  if node == nil then
    return false, nil
  end

  local sig_ctx = xs.xmlSecDSigCtxCreate(mngr)
  if sig_ctx == nil then
    return false, "create signature context failed"
  end

  sig_ctx[0].enabledReferenceUris = 0x0003 -- none, empty, or same document

  if xs.xmlSecDSigCtxVerify(sig_ctx, node) < 0 then
    xs.xmlSecDSigCtxDestroy(sig_ctx)
    return false, "signature verify failed"
  end
      
  local status = sig_ctx[0].status
  xs.xmlSecDSigCtxDestroy(sig_ctx)
  return (status == xs.xmlSecDSigStatusSucceeded), nil
end

--[[---
Verify a signature for a string
@tparam xmlSecKeyPtr cert
@tparam string sig_alg
@tparam string data
@tparam string signature
@treturn bool valid
@treturn ?string error
@see constants:SIGNATURE_ALGORITHMS
]]
function _M.verify_binary(cert, sig_alg, data, signature)
  assert(initialized)

  local trans_ctx = xs.xmlSecTransformCtxCreate()
  if trans_ctx == nil then
    return false, "transform ctx create failed"
  end

  if xs.xmlSecTransformCtxInitialize(trans_ctx) < 0 then
    xs.xmlSecTransformCtxDestroy(trans_ctx)
    return false, "transform ctx initialize failed"
  end

  local transform_id = xs.xmlSecTransformIdListFindByHref(xs.xmlSecTransformIdsGet(), sig_alg, 0xFFFF)
  if transform_id == nil then
    xs.xmlSecTransformCtxDestroy(trans_ctx)
    return false, "transform not found"
  end

  if xs.xmlSecPtrListAdd(trans_ctx[0].enabledTransforms, ffi.cast("void*", transform_id)) < 0 then
    xs.xmlSecTransformCtxDestroy(trans_ctx)
    return false, "transform enable failed"
  end

  local trans = xs.xmlSecTransformCtxCreateAndAppend(trans_ctx, transform_id)
  if trans == nil then
    xs.xmlSecTransformCtxDestroy(trans_ctx)
    return false, "transform add to context failed"
  end

  trans[0].operation = xs.xmlSecTransformOperationVerify

  if xs.xmlSecTransformSetKey(trans, cert) < 0 then
    xs.xmlSecTransformCtxDestroy(trans_ctx)
    return false, "set key failed"
  end

  if xs.xmlSecTransformCtxBinaryExecute(trans_ctx, data, #data) < 0 then
    xs.xmlSecTransformCtxDestroy(trans_ctx)
    return false, "binary execution failed"
  end

  if trans_ctx[0].status ~= xs.xmlSecTransformStatusFinished then
    xs.xmlSecTransformCtxDestroy(trans_ctx)
    return false, "transform context status unknown"
  end

  if xs.xmlSecTransformVerify(trans, signature, #signature, trans_ctx) < 0 then
    xs.xmlSecTransformCtxDestroy(trans_ctx)
    return false, "transform verify failed"
  end

  local status = trans[0].status
  xs.xmlSecTransformCtxDestroy(trans_ctx)
  return (status == xs.xmlSecTransformStatusOk), nil
end

return _M
