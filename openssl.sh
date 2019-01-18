#!/bin/sh
cipher=$( echo "hello world" | openssl enc -e -aes-256-cbc -base64 -md sha256 -k password )
echo $cipher
text=$( echo "$cipher" | openssl enc -d -aes-256-cbc -base64 -md sha256 -k password )
echo $text

echo "U2FsdGVkX19bxTOiHi3yo27kahBe3a+s/aWBCKFyu58=" | \
	openssl enc -d -aes-256-cbc -base64 -md sha256 \
	-k password \
	-iv DF4B47FE61D07975566919B0FEDDCE20