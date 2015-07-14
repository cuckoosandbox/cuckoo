#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

from os import system
from datetime import datetime

def set_wallclock(clock_str, **kwargs):
    clock = datetime.strptime(clock_str, "%Y%m%dT%H:%M:%S")
    # NOTE: On OS X there's `date` utility that accepts
    # new date/time as a string of the folowing format:
    # {month}{day}{hour}{minutes}{year}.{seconds}
    # where every {x} is a 2 digit number.
    cmd = "sudo date {0}".format(clock.strftime("%m%d%H%M%y.%S"))

    if "just_testing" in kwargs:
        return cmd
    else:
        system(cmd)
