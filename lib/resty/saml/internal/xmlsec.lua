local ffi = require "ffi"
require "resty.saml.internal.xml" -- must be loaded before xmlsec

ffi.cdef(require("resty.saml.internal.xmlsec-cdef"))

local _M = {}

setmetatable(_M, {
  __index = ffi.load("libxmlsec1")
})

local _METHODS = {
  Init={"int"},
  Shutdown={"int"},

  TransformSha1GetKlass={"xmlSecTransformId"},
  TransformRsaSha512GetKlass={"xmlSecTransformId"},

  AppInit={"int", "const char*"},
  AppShutdown={"int"},
  AppDefaultKeysMngrInit={"int", "xmlSecKeysMngrPtr"},
  AppDefaultKeysMngrAdoptKey={"int", "xmlSecKeysMngrPtr", "xmlSecKeyPtr"},
  AppDefaultKeysMngrLoad={"int", "xmlSecKeysMngrPtr", "const char*"},
  AppDefaultKeysMngrSave={"int", "xmlSecKeysMngrPtr", "const char*", "xmlSecKeyDataType"},
  AppKeysMngrCertLoad={"int", "xmlSecKeysMngrPtr", "const char*", "xmlSecKeyDataFormat", "xmlSecKeyDataType"},
  AppKeysMngrCertLoadMemory={"int", "xmlSecKeysMngrPtr", "const xmlSecByte*", "xmlSecSize", "xmlSecKeyDataFormat", "xmlSecKeyDataType"},
  AppKeyLoad={"xmlSecKeyPtr", "const char*", "xmlSecKeyDataFormat", "const char*", "void*", "void*"},
  AppKeyLoadMemory={"xmlSecKeyPtr", "const xmlSecByte*", "xmlSecSize", "xmlSecKeyDataFormat", "const char*", "void*", "void*"},
  AppKeyCertLoad={"int", "xmlSecKeyPtr", "const char*", "xmlSecKeyDataFormat"},
  AppKeyCertLoadMemory={"int", "xmlSecKeyPtr", "const xmlSecByte*", "xmlSecSize", "xmlSecKeyDataFormat"},
  AppGetDefaultPwdCallback={"void*"},
}

local _PREFIXES = {
  grcypt="GCrypt",
  gnutls="GnuTLS",
  mscng="MSCng",
  mscrypto="MSCrypto",
  nss="Nss",
  openssl="OpenSSL",
}

local function sig(name, types)
  local s = string.format("%s %s(", types[1], name)
  if types[2] then
    s = s .. types[2]
    for _, arg in next, types, 2 do
      s = s .. ", " .. arg
    end
  end
  return s .. ");"
end

local crypto = nil -- this won't get GC'ed
function _M.load_crypto(lib)
  if crypto then return end
  local prefix = "xmlSec" .. assert(_PREFIXES[lib])
  local cdef = ""
  for m, types in pairs(_METHODS) do
    cdef = cdef .. sig(prefix .. m, types) .. "\n"
  end
  ffi.cdef(cdef)
  crypto = ffi.load("libxmlsec1-" .. lib)
  for m, _ in pairs(_METHODS) do
    _M["xmlSecCrypto" .. m] = crypto[prefix .. m]
  end

  _M["xmlSecTransformSha1Id"] = _M.xmlSecCryptoTransformSha1GetKlass()

  _M["xmlSecTransformExclC14NId"] = _M.xmlSecTransformExclC14NGetKlass()
  _M["xmlSecTransformEnvelopedId"] = _M.xmlSecTransformEnvelopedGetKlass()
end

return _M
