#!/bin/bash
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

echo "$PWD/clean.sh has been deprecated!" >&2
echo "Please start using ./cuckoo.py --clean which also drops database tables."

# I'm sure this can be done easier, but I'm not very familiar with bash
# scripting.. So, here we go. Also, this only works from "./cuckoo" and
# "./cuckoo/utils" directory, but it's still better than before.
if [[ "$PWD/" = */utils/ ]]; then
    export PWD="${PWD:0:${#PWD}-6}"
fi

rm -rf "$PWD/db/" "$PWD/log/" "$PWD/storage/"
find "$PWD/" -name '*.pyc' -exec rm {} \;
