#!/usr/bin/env bash

url=${1:-http://www.npr.org/index.html}
wget -H -p -nd --delete-after -nv -e robots=off ${url}
