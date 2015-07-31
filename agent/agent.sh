#!/bin/bash
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

FILEPATH=$(readlink -f ${0%})
FILEPATHDIR=$(dirname $FILEPATH)

cd /tmp/
python $FILEPATHDIR/agent.py >$FILEPATHDIR/agent.stdout 2>$FILEPATHDIR/agent.stderr &

