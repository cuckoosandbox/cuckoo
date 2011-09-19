#!/usr/bin/python
# Cuckoo Sandbox - Automated Malware Analysis
# Copyright (C) 2010-2011  Claudio "nex" Guarnieri (nex@cuckoobox.org)
# http://www.cuckoobox.org
#
# This file is part of Cuckoo.
#
# Cuckoo is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Cuckoo is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/.

import os
import sys
import sqlite3
from optparse import OptionParser

from cuckoo.core.now import *
from cuckoo.core.logo import *
from cuckoo.core.colors import *
from cuckoo.core.config import *

# This is a quick hacky script to add analysis tasks to the queue database
# through the command line.
def main():
    parser = OptionParser(usage="usage: %prog [options] filepath")
    parser.add_option("-t", "--timeout",
                      action="store",
                      type="int",
                      dest="timeout",
                      default=None,
                      help="Specify analysis execution time limit")
    parser.add_option("-p", "--package",
                      action="store",
                      type="string",
                      dest="package",
                      default=None,
                      help="Specify custom analysis package name")
    parser.add_option("-r", "--priority",
                      action="store",
                      type="int",
                      dest="priority",
                      default=None,
                      help="Specify an analysis priority expressed in integer")
    parser.add_option("-c", "--custom",
                      action="store",
                      type="string",
                      dest="custom",
                      default=None,
                      help="Specify any custom value to be passed to postprocessing")

    (options, args) = parser.parse_args()

    # Check if the target file path has been specified, otherwise terminate
    # script.
    if len(args) != 1:
        parser.error("You didn't specify the target file path")
        return False

    target = args[0]

    # Check if the target file actually exists, otherwise terminate script.
    if not os.path.exists(target):
        print bold(red("ERROR")) + ": The target file \"%s\" does not exist." % target
        return False

    # Try to connect to SQLite Database, if connection fails I need to terminate
    # the script.
    try:
        conn = sqlite3.connect(CuckooConfig().get_localdb())
        cursor = conn.cursor()
    except Exception, why:
        print bold(red("ERROR")) + ": Unable to connect to SQLite database: %s" % why
        return False

    # Check if a similar task already exist in the database. This check is made
    # in case the user accidentally issued the command multiple times. Require
    # confirmation to proceed.
    cursor.execute("SELECT * FROM queue WHERE target = '%s';" % target)
    task = cursor.fetchone()
    if task:
        print bold(yellow("WARNING")) + ": Seems like a task with the target " \
              "\"%s\" already exists in database." % target

        # If the user doesn't really want to add the task, terminate teh script.
        confirm = raw_input("Are you sure you want to add it (yes/no)? ")
        if confirm.lower() == "no":
            print bold(yellow("Stopped")) + ": Task not added. Aborting."
            return False

    # Check if a custom timeout has been specified, in case it's not set default
    # value to NULL.
    if not options.timeout:
        timeout = "NULL"
    else:
        timeout = options.timeout

    # Same thing for analysis package.
    if not options.package:
        package = "NULL"
    else:
        package = "'%s'" % options.package

    # And again for priority.
    if not options.priority:
        priority = "0"
    else:
        priority = options.priority

    if not options.custom:
        custom = "NULL"
    else:
        custom = "'%s'" % options.custom

    # If everything's fine, now add the task to the queue into the database.
    sql = "INSERT INTO queue (target, timeout, package, priority, custom, added_on) " \
          "VALUES ('%s', %s, %s, %s, %s, '%s');"                                  \
          % (target, timeout, package, priority, custom, get_now())

    cursor.execute(sql)
    conn.commit()

    print bold(cyan("Done")) + ": Task added to database!"

    return True

if __name__ == "__main__":
    main()
