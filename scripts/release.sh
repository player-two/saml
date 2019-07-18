#!/bin/bash

TAG=$1
shift

if [ -z $TAG ]; then
  echo "No tag specified"
  exit 1
fi

if [ -z $GITHUB_TOKEN ]; then
  echo "No GitHub OAuth token found"
  exit 1
fi

if [ "$#" == "0" ]; then
  echo "No release artifacts"
  exit 1
fi

STATUS=$(curl https://api.github.com/repos/megalord/saml/releases -H "Authorization: token $GITHUB_TOKEN" -H 'Accept: application/vnd.github.v3+json' -H 'Content-Type: application/json' --data "{\"tag_name\":\"$TAG\",\"name\":\"$TAG\"}" -s -o release.json -w "%{http_code}")
CURL_STATUS=$?
if [ $CURL_STATUS -ne 0 ]; then
  echo "Could not create release; curl failed with error code $CURL_STATUS"
  rm -f release.json
  exit 1
fi
if [ $STATUS -ne 201 ]; then
  echo "Could not create release; GitHub returned $STATUS"
  cat release.json
  rm -f release.json
  exit 1
fi

id=`cat release.json | python -c 'import json, sys; print(json.load(sys.stdin)["id"])'`
if [ ! -z $id ]; then
  echo "Release $id created"
  rm -f release.json
else
  echo "Release not found; see release.json"
  exit 1
fi

for file in "$@"; do
  name=`basename $file`
  echo "Uploading release asset $name"

  STATUS=$(curl https://uploads.github.com/repos/megalord/saml/releases/$id/assets?name=$name -H "Authorization: token $GITHUB_TOKEN" -H 'Accept: application/vnd.github.v3+json' -H 'Content-Type: application/gzip' --data-binary "@$file" -s -o /dev/null -w "%{http_code}")
  CURL_STATUS=$?
  if [ $CURL_STATUS -ne 0 ]; then
    echo "Could not create release asset $name; curl failed with error code $CURL_STATUS"
    exit 1
  fi
  if [ $STATUS -ne 201 ]; then
    echo "Could not create release asset $name; GitHub returned $STATUS"
    exit 1
  fi
done
