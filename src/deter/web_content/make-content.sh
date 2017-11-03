#!/usr/bin/env bash

# this script is an example of how to mirror a real web page that can be used
# as input to the deploy script

wget --trust-server-names -H -p -e robots=off -w 0.25 $1
# fix this hack...
python ~/web_content/fixup .
