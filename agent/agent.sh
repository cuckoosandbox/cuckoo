#!/bin/bash
# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

FILEPATH=$(readlink -f ${0%})
FILEPATHDIR=$(dirname $FILEPATH)

cd /tmp/
python $FILEPATHDIR/agent.py >$FILEPATHDIR/agent.stdout 2>$FILEPATHDIR/agent.stderr &

