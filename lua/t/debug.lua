-- Scratch pad for narrowing the cause of a specific error
local utils = require "t.utils"

saml.init({ debug=true, data_dir="../data/" })

local key = assert(saml.key_read_file("t/data/sp.key", saml.KeyDataFormatPem))
local authn_request = assert(utils.readfile("t/data/authn_request.xml"))
local query_string = assert(saml.binding_redirect_create(key, "SAMLRequest", authn_request, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", "/"))
print(query_string)
