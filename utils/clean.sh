#!/bin/bash
# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

rm -rf ../db/ ../log/ ../storage/
find ../ -name '*.pyc' -exec rm {} \;
