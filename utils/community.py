#!/usr/bin/env python
# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import shutil
import urllib2
import argparse
import tempfile
from zipfile import ZipFile
from StringIO import StringIO

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

import lib.cuckoo.common.colors as colors
from lib.cuckoo.common.constants import CUCKOO_ROOT

URL = "https://github.com/cuckoobox/community/archive/{0}.zip"

def download_archive():
    print("Downloading modules from {0}".format(URL))

    try:
        data = urllib2.urlopen(URL).read()
    except Exception as e:
        print("ERROR: Unable to download archive: %s" % e)
        sys.exit(-1)

    zip_data = StringIO()
    zip_data.write(data)
    archive = ZipFile(zip_data, "r")
    temp_dir = tempfile.mkdtemp()
    archive.extractall(temp_dir)
    archive.close()
    final_dir = os.path.join(temp_dir, os.listdir(temp_dir)[0])

    return temp_dir, final_dir


def install(enabled, force, rewrite):
    (temp, source) = download_archive()

    folders = {
        "signatures": os.path.join("modules", "signatures"),
        "processing": os.path.join("modules", "processing"),
        "reporting": os.path.join("modules", "reporting"),
        "machinemanagers": os.path.join("modules", "machinemanagers")
    }

    for category in enabled:
        folder = folders[category]

        print("\nInstalling {0}".format(colors.cyan(category.upper())))

        origin = os.path.join(source, folder)

        for file_name in os.listdir(origin):
            if file_name == ".gitignore":
                continue

            destination = os.path.join(CUCKOO_ROOT, folder, file_name)

            if not rewrite:
                if os.path.exists(destination):
                    print("File \"{0}\" already exists, "
                          "{1}".format(file_name, colors.yellow("skipped")))
                    continue

            install = False

            if not force:
                while 1:
                    choice = raw_input("Do you want to install file "
                                       "\"{0}\"? [yes/no] ".format(file_name))
                    if choice.lower() == "yes":
                        install = True
                        break
                    elif choice.lower() == "no":
                        break
                    else:
                        continue
            else:
                install = True

            if install:
                shutil.copy(os.path.join(origin, file_name), destination)
                print("File \"{0}\" {1}".format(file_name,
                                                colors.green("installed")))

    shutil.rmtree(temp)

def main():
    global URL

    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--all", help="Download everything", action="store_true", required=False)
    parser.add_argument("-s", "--signatures", help="Download Cuckoo signatures", action="store_true", required=False)
    parser.add_argument("-p", "--processing", help="Download processing modules", action="store_true", required=False)
    parser.add_argument("-m", "--machinemanagers", help="Download machine managers",action="store_true", required=False)
    parser.add_argument("-r", "--reporting", help="Download reporting modules", action="store_true", required=False)
    parser.add_argument("-f", "--force", help="Install files without confirmation", action="store_true", required=False)
    parser.add_argument("-w", "--rewrite", help="Rewrite existing files", action="store_true", required=False)
    parser.add_argument("-b", "--branch", help="Specify a different branch", action="store", default="master", required=False)
    args = parser.parse_args()

    enabled = []
    force = False
    rewrite = False

    if args.all:
        enabled.append("processing")
        enabled.append("signatures")
        enabled.append("reporting")
        enabled.append("machinemanagers")
    else:
        if args.signatures:
            enabled.append("signatures")
        if args.processing:
            enabled.append("processing")
        if args.reporting:
            enabled.append("reporting")
        if args.machinemanagers:
            enabled.append("machinemanagers")

    if not enabled:
        print(colors.red("You need to enable some category!\n"))
        parser.print_help()
        return

    if args.force:
        force = True
    if args.rewrite:
        rewrite = True

    URL = URL.format(args.branch)

    install(enabled, force, rewrite)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
