#!/bin/bash -e

# Fetch the bundle of SAML XSDs, then download all imported XSDs and convert their import paths from remote to local.
# This is dumb, but not as dumb as the validator having to use the network.

schema_dir=`pwd`/data/xsd

function resolve_schema_locations {
  q=$1
  schemas=$(grep -r "schemaLocation=${q}http" $schema_dir | cut -d${q} -f 2 | sort | uniq)
  for s in $schemas; do
    f=${s##*/}
    if [ -z "$f" ]; then
      f=$(echo $f | md5sum | cut -d" " -f1).xsd
    fi

    if [ -e "$schema_dir/$f" ]; then
      echo "skipping download for $f"
    else
      echo "$s -> $schema_dir/$f"
      curl $s -s -o $schema_dir/$f
    fi
    sed -i -e "s|schemaLocation=${q}${s}${q}|schemaLocation=${q}${f}${q}|" $schema_dir/*.xsd
  done
}

rm -rf $schema_dir
mkdir -p $schema_dir
zipfile=saml-2.0-os-xsd.zip
curl https://docs.oasis-open.org/security/saml/v2.0/$zipfile -s -o $zipfile; unzip -d $schema_dir $zipfile; rm $zipfile
resolve_schema_locations '"'
resolve_schema_locations "'"
