# Copyright (C) 2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import getpass
import os
import shutil
import stat
import sys

import xml.etree.ElementTree as ET

ns = {
    "vbox": "http://www.virtualbox.org/",
}

def mkdir(dirpath):
    if not os.path.exists(dirpath):
        os.mkdir(dirpath)

def symlink(src, dst):
    if not os.path.lexists(dst):
        os.symlink(src, dst)

def index_vdi(vmcloakdir):
    images, readonly, temporary = [], [], []

    for filename in os.listdir(os.path.join(vmcloakdir, "image")):
        filepath = os.path.join(vmcloakdir, "image", filename)
        images.append((filename, os.path.getsize(filepath)))

    for snapshot in os.listdir(os.path.join(vmcloakdir, "vms")):
        filepath = os.path.join(
            vmcloakdir, "vms", snapshot, "%s.vbox" % snapshot
        )
        root = ET.fromstring(open(filepath, "rb").read())

        obj = root.findall(".//vbox:Snapshot//vbox:Image", ns)
        assert len(obj) == 1
        filepath = os.path.join(
            vmcloakdir, "vms", snapshot, "Snapshots",
            "%s.vdi" % obj[0].attrib["uuid"]
        )
        readonly.append((
            snapshot, obj[0].attrib["uuid"], os.path.getsize(filepath)
        ))

        obj = root.findall(
            ".//vbox:Machine/vbox:StorageControllers//vbox:Image", ns
        )
        assert len(obj) == 1
        temporary.append((snapshot, obj[0].attrib["uuid"]))
    return images, readonly, temporary

if __name__ == "__main__":
    print "Welcome to %s!" % sys.argv[0]
    print "This script turns a VMCloak-based directory into a"
    print "high-performance setup for high volume setups."
    print

    if len(sys.argv) != 3 and len(sys.argv) != 4:
        print "Usage: python %s [-t] <vmmount> <tmpmount>" % sys.argv[0]
        print
        print "Input:  ~/.vmcloak"
        print "Output: vmmount   tmpfs-based VM storage (readonly)"
        print "Output: tmpmount  temporary VM changes mount"
        print
        print "Note that the VDI files located at tmpmount will grow"
        print "in size during execution as samples write data to disk."
        exit(1)

    tmpfs = False
    if sys.argv[1] == "-t":
        tmpfs = True
        sys.argv.pop(1)

    vmmount, tmpmount = sys.argv[1:]

    vmcloakdir = os.path.expanduser("~/.vmcloak")
    backupdir = "%s.backup" % vmcloakdir
    user = getpass.getuser()

    if os.path.exists(backupdir):
        images, readonly, temporary = index_vdi(backupdir)
    else:
        images, readonly, temporary = index_vdi(vmcloakdir)

    vmsize = sum(filesize for snapshot, vdiname, filesize in readonly)
    vmsize += sum(filesize for filename, filesize in images)
    vmsize = vmsize / 1024**3 + 1

    if not os.path.exists(vmmount):
        print "# Please run the following commands first!"
        print "# (Assuming the tmpfs mount is not yet in-place!)"
        print "$ sudo mkdir -p %s" % vmmount
        if tmpfs:
            print "$ sudo mount -t tmpfs -o size=%dG tmpfs %s" % (
                vmsize, vmmount
            )
        print "$ sudo chown %s:%s %s" % (user, user, vmmount)
        exit(0)

    parentvfs = os.statvfs(os.path.dirname(vmmount))
    if tmpfs and parentvfs.f_blocks == os.statvfs(vmmount).f_blocks:
        print "# Did you initialize the tmpfs mount yet?"
        print "$ sudo mount -t tmpfs -o size=%dG tmpfs %s" % (
            vmsize, vmmount
        )
        print "$ sudo chown %s:%s %s" % (user, user, vmmount)
        exit(0)

    print "Moving original ~/.vmcloak to ~/.vmcloak.backup .."
    print "Installing symbolic links etc .."

    if not os.path.exists(backupdir):
        shutil.move(vmcloakdir, backupdir)

    # Now populate the new ~/.vmcloak directory.
    mkdir(vmcloakdir)

    mkdir(os.path.join(vmcloakdir, "image"))
    for filename, filesize in images:
        symlink(
            os.path.join(vmmount, filename),
            os.path.join(vmcloakdir, "image", filename)
        )

    mkdir(os.path.join(tmpmount, "vms"))
    symlink(
        os.path.join(tmpmount, "vms"), os.path.join(vmcloakdir, "vms")
    )

    for snapshot, vdiname, filesize in readonly:
        mkdir(os.path.join(tmpmount, "vms", snapshot))
        mkdir(os.path.join(tmpmount, "vms", snapshot, "Snapshots"))
        symlink(
            os.path.join(vmmount, "%s.vdi" % vdiname),
            os.path.join(
                vmcloakdir, "vms", snapshot,
                "Snapshots", "%s.vdi" % vdiname
            )
        )

    symlink(
        os.path.join(backupdir, "deps"),
        os.path.join(vmcloakdir, "deps")
    )
    symlink(
        os.path.join(backupdir, "iso"),
        os.path.join(vmcloakdir, "iso")
    )

    print "Copying ~/.vmcloak.backup files to new locations.."

    shutil.copy(os.path.join(backupdir, "repository.db"), vmcloakdir)

    for filename, filesize in images:
        shutil.copy(
            os.path.join(backupdir, "image", filename),
            os.path.join(vmmount, filename)
        )
        os.chmod(os.path.join(vmmount, filename), stat.S_IREAD)

    for snapshot, vdiname, filesize in readonly:
        shutil.copy(
            os.path.join(backupdir, "vms", snapshot, "%s.vbox" % snapshot),
            os.path.join(vmcloakdir, "vms", snapshot, "%s.vbox" % snapshot)
        )

        shutil.copy(
            os.path.join(
                backupdir, "vms", snapshot, "Snapshots", "%s.vdi" % vdiname
            ),
            os.path.join(vmmount, "%s.vdi" % vdiname)
        )
        os.chmod(os.path.join(vmmount, "%s.vdi" % vdiname), stat.S_IREAD)

    for snapshot, vdiname in temporary:
        backsnapdir = os.path.join(backupdir, "vms", snapshot, "Snapshots")
        tempsnapdir = os.path.join(tmpmount, "vms", snapshot, "Snapshots")

        shutil.copy(
            os.path.join(backsnapdir, "%s.vdi" % vdiname),
            os.path.join(tempsnapdir, "%s.vdi" % vdiname)
        )

        for filename in os.listdir(backsnapdir):
            if filename.endswith(".sav"):
                shutil.copy(
                    os.path.join(backsnapdir, filename),
                    os.path.join(tempsnapdir, filename)
                )
                break
