package = "lua-resty-saml"
version = "dev-1"
source = {
  url = "git://github.com/megalord/lua-resty-saml.git"
}
description = {
  summary = "Provides SAML support for OpenResty",
  homepage = "https://megalord.github.io/lua-resty-saml/",
  license = "MIT",
}
dependencies = {
  "lua >= 5.1",
  "lua-zlib",
}
external_dependencies = {
  LIBXML2 = {
    library = "xml2"
  },
  XMLSEC1 = {
    library = "xmlsec1"
  },
}
build = {
  type = "make",
  build_variables = {
    CFLAGS="$(CFLAGS)",
    LDFLAGS="$(LDFLAGS)",
    LIBFLAG="$(LIBFLAG)",
    LUA_INCDIR="$(LUA_INCDIR)",
    LIBXML2_LIBDIR="$(LIBXML2_LIBDIR)",
    LIBXML2_INCDIR="$(LIBXML2_INCDIR)",
    XMLSEC1_LIBDIR="$(XMLSEC1_LIBDIR)",
    XMLSEC1_INCDIR="$(XMLSEC1_INCDIR)",
  },
  install_variables = {
    INST_LIBDIR="$(LIBDIR)",
    INST_LUADIR="$(LUADIR)",
    INST_CONFDIR="$(CONFDIR)",
  },
  copy_directories = {
    "data",
  },
}
