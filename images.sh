#!/bin/bash -e

docker build -t resty-saml .
docker build -t resty-saml-docs docs
docker build -t resty-saml-test t
