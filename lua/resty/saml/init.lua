--[[---
Namespace for all library functions
@module resty.saml
@see saml
@see resty.saml.binding
]]

local _M = require "saml"

_M.binding = require "resty.saml.binding"

return _M
