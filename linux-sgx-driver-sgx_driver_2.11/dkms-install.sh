#!/bin/bash -e

VERSION="0.10"

if ! dkms status -m isgx -v "$VERSION" | grep -q 'added\|built\|installed' ; then
  dkms add -m isgx -v "$VERSION"
fi

dkms build -m isgx -v "$VERSION" --verbose
dkms install -m isgx -v "$VERSION"