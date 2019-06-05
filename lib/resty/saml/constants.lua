--[[---
Constants to be used as arguments for other methods
]]

local ffi = require "ffi"
local xs  = require "resty.saml.internal.xmlsec"

--[[---
Namespaces for XML documents
@table XMLNS
@field ASSERTION
@field PROTOCOL
]]

--[[---
@table BINDINGS
@field HTTP_POST
@field HTTP_REDIRECT
]]

--[[---
Supported signature algorithms
@table SIGNATURE_ALGORITHMS
@field RSA_SHA256
@field RSA_SHA512
]]

return {
  BINDINGS = {
    HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
    HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
  },
  SIGNATURE_ALGORITHMS = {
    RSA_SHA256 = ffi.string(assert(xs.xmlSecHrefRsaSha256)),
    RSA_SHA512 = ffi.string(assert(xs.xmlSecHrefRsaSha512)),
  },
  STATUS_CODES = {
    SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success",
    REQUESTER = "urn:oasis:names:tc:SAML:2.0:status:Requester",
    RESPONDER = "urn:oasis:names:tc:SAML:2.0:status:Responder",
    VERSION_MISMATCH = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch",
  },
  XMLNS = {
    ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion",
    PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol",
  },
}
