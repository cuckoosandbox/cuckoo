#!/bin/bash
FILEPATH=$(readlink -f ${0%})
FILEPATHDIR=$(dirname $FILEPATH)

cd /tmp/
python $FILEPATHDIR/agent.py >$FILEPATHDIR/agent.stdout 2>$FILEPATHDIR/agent.stderr &

