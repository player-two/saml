#!/bin/sh -e

args="$*"
if [ "$args" == "" ]; then
  args='.'
fi

OPENRESTY_HOME=/usr/local/openresty

docker run --rm -it \
  -v `pwd`/lib/resty/:$OPENRESTY_HOME/luajit/share/lua/5.1/resty/ \
  -v `pwd`/data:/data \
  -v `pwd`/saml.c:/tmp/saml.c \
  -v `pwd`/Makefile:/tmp/Makefile \
  -v `pwd`/t:/t \
  -w /t \
  -e LD_LIBRARY_PATH=$OPENRESTY_HOME/luajit/lib:/usr/local/lib \
  resty-saml-test:latest \
  bash -c "cd /tmp && make build && cp saml.so $OPENRESTY_HOME/lualib/ && cd /t && busted -lpath /usr/local/openresty/lualib/?.lua -cpath /usr/local/openresty/lualib/?.so $args"
