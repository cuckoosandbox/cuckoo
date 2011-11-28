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
import hashlib
import urllib2
from optparse import OptionParser

from cuckoo.core.db import *
from cuckoo.logging.colors import *
from cuckoo.config.config import *

DESTINATION = "/tmp/"

def filename_from_url(url):
    return url.split('/')[-1].split('#')[0].split('?')[0]

def download(url):
    print(bold(cyan("INFO")) + ": Downloading URL %s" % url)

    try:
        url_handle = urllib2.urlopen(url)
        binary_data = url_handle.read()
    except Exception, why:
        print(bold(red("ERROR")) + ": Unable to download file: %s" % why)
        return False

    filename = filename_from_url(url)

    try:
        dest = os.path.join(DESTINATION, filename)
        f = open(dest, "wb")
        f.write(binary_data)
        f.close()
    except Exception, why:
        print(bold(red("ERROR")) + ": Unable to store file: %s" % why)
        return False

    return dest

def url(url):
    file_path = os.path.join(DESTINATION, "%s.url" % hashlib.md5(url).hexdigest())
    file_handle = open(file_path, "w")
    file_handle.write("[InternetShortcut]\n")
    file_handle.write("URL=%s\n" % url)
    file_handle.close()
    return file_path

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
    parser.add_option("-d", "--download",
                      action="store_true",
                      dest="download",
                      default=False,
                      help = "Specify if the target is an URL to be downloaded")
    parser.add_option("-u", "--url",
                      action="store_true",
                      dest="url",
                      default=False,
                      help = "Specify if the target is an URL to be analyzed")

    (options, args) = parser.parse_args()

    # Check if the target file path has been specified, otherwise terminate
    # script.
    if len(args) != 1:
        parser.error("You didn't specify the target file path")
        return False

    # If the specified argument is an URL, download it first and retrieve the
    # generated path.
    if options.download:
        target = download(args[0])
    # If the specified argument is an URL to be analyzed, generate .url file.
    elif options.url:
        target = url(args[0])
        # If the user didn't specify any analysis package, I'll use the default
        # Internet Explorer package.
        if not options.package:
            print(bold(yellow("NOTICE")) + ": You submitted an URL to be analyzed " \
                  "but didn't specify any package, I'm gonna user the default " \
                  "Internet Explorer package.")
            options.package = "ie"
    # Otherwise just assign the argument to target path.
    else:
        target = args[0]

    if not target:
        return False

    # Check if the target file actually exists, otherwise terminate script.
    if not os.path.exists(target):
        print(bold(red("ERROR")) + ": The target file \"%s\" does not exist." % target)
        return False

    # Add task to the database.
    try:
        db = CuckooDatabase()
        task_id = db.add_task(target,
                              options.timeout,
                              options.package,
                              options.priority,
                              options.custom)
        if not task_id:
            print(bold(red("ERROR")) + ": Unable to add task to database.")
            return False
        else:
            print(bold(cyan("DONE")) + ": Task successfully added with ID %d."
                  % task_id)
    except Exception, why:
        print(bold(red("ERROR")) + ": Unable to add new task: %s" % why)
        return False

    return True

if __name__ == "__main__":
    main()
