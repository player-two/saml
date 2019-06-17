project = "lua-resty-saml"
title = "lua-resty-saml documentation"
description = "An OpenResty plugin for Single Sign-On via SAML"
full_description = [[
Welcome to the documentation for lua-resty-saml!  See @{00-Introduction.md} to get started.
]]

dir = "../out"

format = "markdown"
style = "!pale"

topics = {
  "00-Introduction.md",
  "01-Installation.md",
  "02-Organization.md",
}

file = {
  "../lib/",
  "../lua_saml.c",
}

examples = "../example"
