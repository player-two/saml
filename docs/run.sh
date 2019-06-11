#!/bin/sh -e

base=/build

docker run --rm -it \
  -v `pwd`/docs:$base/docs \
  -v `pwd`/example:$base/example \
  -v `pwd`/out:$base/out \
  -v `pwd`/lib:$base/lib \
  -v `pwd`/lua_saml.c:$base/lua_saml.c \
  -w $base/docs \
  resty-saml-docs:latest \
  ldoc .
