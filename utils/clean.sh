#!/bin/bash
# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

# PWD equals top level folder "cuckoo"
PWD=${PWD/cuckoo*/cuckoo\/}

if [[ $PWD = */cuckoo*/ ]]; then
    rm -rf $PWD/db/ $PWD/log/ $PWD/storage/
    find $PWD/ -name '*.pyc' -exec rm {} \;
fi
