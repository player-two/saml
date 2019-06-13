#!/bin/sh -e

NAME=resty-saml-example

echo `pwd`
docker run --rm -it --name $NAME \
  -v `pwd`/lib/:/tmp/lib/ \
  -v `pwd`/data:/tmp/data \
  -v `pwd`/saml.h:/tmp/saml.h \
  -v `pwd`/saml.c:/tmp/saml.c \
  -v `pwd`/lua_saml.c:/tmp/lua_saml.c \
  -v `pwd`/Makefile:/tmp/Makefile \
  -v `pwd`/lua-resty-saml-dev-1.rockspec:/tmp/lua-resty-saml-dev-1.rockspec \
  -v `pwd`/t/data:/ssl \
  -v `pwd`/example:/example \
  -p 8088:8088 \
  -p 8089:8089 \
  resty-saml:latest \
  bash -c "cd /tmp && luarocks make && cd /example && openresty -c /example/nginx.conf -g 'daemon off;'"
