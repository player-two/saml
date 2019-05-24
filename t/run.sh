#!/bin/sh -e

args="$*"
if [ "$args" == "" ]; then
  args='.'
fi

OPENRESTY_HOME=/usr/local/openresty

docker run --rm -it \
  -v `pwd`/lib/resty/:$OPENRESTY_HOME/luajit/share/lua/5.1/resty/ \
  -v `pwd`/data:/data \
  -v `pwd`/t:/t \
  -w /t \
  resty-saml-test:latest \
  bash -c "busted -lpath /usr/local/openresty/lualib/?.lua $args"
