#!/bin/sh -e

OPENRESTY_HOME=/usr/local/openresty
NAME=resty-saml-example

echo `pwd`
docker run --rm -it --name $NAME \
  -v `pwd`/lib/resty/:$OPENRESTY_HOME/luajit/share/lua/5.1/resty/ \
  -v `pwd`/data:/data \
  -v `pwd`/t/data:/ssl \
  -v `pwd`/example:/example \
  -p 8088:8088 \
  -p 8089:8089 \
  -w /example \
  resty-saml:latest \
  bash -c "openresty -c /example/nginx.conf -g 'daemon off;'"
