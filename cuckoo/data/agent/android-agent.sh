# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

export TMPDIR=/data/local/tmp
cd $TMPDIR

nohup usr/bin/python3 agent.py >/dev/null 2>&1 &
