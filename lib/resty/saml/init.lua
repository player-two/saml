--[[---
Namespace for all library functions
@see saml
@see resty.saml.binding
]]

local _M = require "saml"

_M.binding = require "resty.saml.binding"

return _M
