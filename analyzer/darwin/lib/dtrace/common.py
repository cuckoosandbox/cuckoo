#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

from os import path
from time import sleep

def sanitize_path(raw_path):
    """ Replace spaces with backslashes+spaces """
    return raw_path.replace(" ", "\\ ")

def path_for_script(script):
    """ Return the full path for the given script """
    return path.join(current_directory(), script)

def current_directory():
    return path.dirname(path.abspath(__file__))

def filelines(source_file):
    """ A generator that returns lines of the file.
    If there're no new lines it waits until the file is updated.
    """
    # Go to the end of the file
    source_file.seek(0, 2)
    while True:
        line = source_file.readline()
        if not line:
            # Sleep briefly
            sleep(0.1)
            continue
        yield line
