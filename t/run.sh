#!/bin/sh -e

args="$*"
if [ "$args" == "" ]; then
  args='.'
fi

OPENRESTY_HOME=/usr/local/openresty

docker run --rm -it \
  -v `pwd`/lib/:/tmp/lib/ \
  -v `pwd`/data:/tmp/data \
  -v `pwd`/saml.h:/tmp/saml.h \
  -v `pwd`/saml.c:/tmp/saml.c \
  -v `pwd`/lua_saml.c:/tmp/lua_saml.c \
  -v `pwd`/Makefile:/tmp/Makefile \
  -v `pwd`/lua-resty-saml-dev-1.rockspec:/tmp/lua-resty-saml-dev-1.rockspec \
  -v `pwd`/t:/t \
  -w /t \
  -e ROCK_DIR=$OPENRESTY_HOME/luajit/lib/luarocks/rocks/lua-resty-saml/dev-1/ \
  resty-saml-test:latest \
  bash -c "cd /tmp && luarocks make && cd /t && busted -lpath /usr/local/openresty/lualib/?.lua -cpath /usr/local/openresty/lualib/?.so $args"
