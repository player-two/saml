#!/bin/sh -e

base=/build

docker run --rm -it \
  -v `pwd`/docs:$base/docs \
  -v `pwd`/example:$base/example \
  -v `pwd`/out:$base/out \
  -v `pwd`/lib:$base/lib \
  -v `pwd`/saml.c:$base/saml.c \
  -w $base/docs \
  resty-saml-docs:latest \
  ldoc .
