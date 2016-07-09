#!/usr/bin/env python
# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import shutil
import urllib2
import argparse
import tempfile
from tarfile import TarFile

sys.path.insert(0, os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

import lib.cuckoo.common.colors as colors
from lib.cuckoo.common.constants import CUCKOO_ROOT

URL = "https://github.com/cuckoosandbox/community/archive/{0}.tar.gz"

def download_archive():
    print("Downloading modules from {0}".format(URL))

    try:
        data = urllib2.urlopen(URL).read()
    except Exception as e:
        print("ERROR: Unable to download archive: %s" % e)
        sys.exit(-1)

    return data

def extract_archive(data):
    fd, filepath = tempfile.mkstemp()
    os.write(fd, data)
    os.close(fd)

    archive = TarFile.open(filepath, mode="r:gz")
    temp_dir = tempfile.mkdtemp()
    archive.extractall(temp_dir)
    archive.close()
    os.unlink(filepath)
    final_dir = os.path.join(temp_dir, os.listdir(temp_dir)[0])

    return temp_dir, final_dir

def installdir(src, dst, force, rewrite, origin=[]):
    for file_name in os.listdir(src):
        if file_name == ".gitignore":
            continue

        destination = os.path.join(dst, file_name)

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
            srcpath = os.path.join(src, file_name)
            if os.path.islink(srcpath):
                if os.path.lexists(destination):
                    try:
                        shutil.rmtree(destination)
                    except OSError:
                        os.unlink(destination)
                os.symlink(os.readlink(srcpath), destination)
                print "Symbolic link \"%s/%s\" -> \"%s\" %s" % (
                    "/".join(origin), file_name, os.readlink(srcpath),
                    colors.green("installed"))

            elif os.path.isdir(srcpath):
                installdir(srcpath, destination, force, rewrite,
                           origin + [file_name])
            else:
                if not os.path.isdir(os.path.dirname(destination)):
                    os.makedirs(os.path.dirname(destination))

                shutil.copy(srcpath, destination)
                print "File \"%s/%s\" %s" % (
                    "/".join(origin), file_name, colors.green("installed"))


def install(enabled, force, rewrite, archive):
    if archive:
        if not os.path.isfile(archive):
            print("ERROR: Provided archive not found!")
            sys.exit(-1)

        data = open(archive, "rb").read()
    else:
        data = download_archive()

    temp, source = extract_archive(data)

    folders = {
        "signatures": os.path.join("modules", "signatures"),
        "processing": os.path.join("modules", "processing"),
        "reporting": os.path.join("modules", "reporting"),
        "machinery": os.path.join("modules", "machinery"),
        "analyzer": os.path.join("analyzer"),
        "monitor": os.path.join("data", "monitor"),
        "agent": os.path.join("agent"),
    }

    for category in enabled:
        folder = folders[category]

        print("\nInstalling {0}".format(colors.cyan(category.upper())))

        origin = os.path.join(source, folder)
        if not os.path.isdir(origin):
            print "  No candidates available, continuing."
            continue

        installdir(origin, os.path.join(CUCKOO_ROOT, folder), force, rewrite)

    shutil.rmtree(temp)

def main():
    global URL

    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--all", help="Download everything", action="store_true", required=False)
    parser.add_argument("-s", "--signatures", help="Download Cuckoo signatures", action="store_true", required=False)
    parser.add_argument("-p", "--processing", help="Download processing modules", action="store_true", required=False)
    parser.add_argument("-m", "--machinery", help="Download machine managers", action="store_true", required=False)
    parser.add_argument("-n", "--analyzer", help="Download analyzer modules", action="store_true", required=False)
    parser.add_argument("-M", "--monitor", help="Download monitoring binaries", action="store_true", required=False)
    parser.add_argument("-g", "--agent", help="Download agent modules", action="store_true", required=False)
    parser.add_argument("-r", "--reporting", help="Download reporting modules", action="store_true", required=False)
    parser.add_argument("-f", "--force", help="Install files without confirmation", action="store_true", required=False)
    parser.add_argument("-w", "--rewrite", help="Rewrite existing files", action="store_true", required=False)
    parser.add_argument("-b", "--branch", help="Specify a different branch", action="store", default="master", required=False)
    parser.add_argument("archive", help="Install a stored archive", nargs="?")
    args = parser.parse_args()

    enabled = []
    force = False
    rewrite = False

    if args.all:
        enabled.append("processing")
        enabled.append("signatures")
        enabled.append("reporting")
        enabled.append("machinery")
        enabled.append("analyzer")
        enabled.append("monitor")
        enabled.append("agent")
    else:
        if args.signatures:
            enabled.append("signatures")
        if args.processing:
            enabled.append("processing")
        if args.reporting:
            enabled.append("reporting")
        if args.machinery:
            enabled.append("machinery")
        if args.analyzer:
            enabled.append("analyzer")
        if args.agent:
            enabled.append("agent")

    if not enabled:
        print(colors.red("You need to enable some category!\n"))
        parser.print_help()
        return

    if args.force:
        force = True
    if args.rewrite:
        rewrite = True

    URL = URL.format(args.branch)

    install(enabled, force, rewrite, args.archive)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
