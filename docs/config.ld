project = "saml"
title = "saml documentation"
description = "A library for enabling Single Sign-On via SAML"
full_description = [[
Welcome to the documentation for saml!  See @{00-Introduction.md} to get started.
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
  "../lua/resty/",
  "../lua/lua_saml.c",
}

examples = "../lua/example"
