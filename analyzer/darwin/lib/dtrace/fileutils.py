#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This file is part of my GSoC'15 project for Cuckoo Sandbox:
#	http://www.cuckoosandbox.org
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

from time import sleep

def filelines(file):
    """ A generator that returns lines of the file. If there're no new lines,
    it waits until the file is updated.
    """
    # Go to the end of the file
    file.seek(0,2)
    while True:
        line = file.readline()
        if not line:
            # Sleep briefly
            sleep(0.1)
            continue
        yield line
