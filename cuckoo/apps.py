# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import fnmatch
import logging
import os.path
import requests
import StringIO
import tarfile

from cuckoo.common.colors import bold, red, yellow
from cuckoo.common.utils import to_unicode
from cuckoo.core.database import Database
from cuckoo.misc import cwd, mkdir

log = logging.getLogger(__name__)

URL = "https://github.com/cuckoosandbox/community/archive/%s.tar.gz"

def fetch_community(branch="master", force=False, filepath=None):
    if filepath:
        buf = open(filepath, "rb").read()
    else:
        buf = requests.get(URL % branch).content

    t = tarfile.TarFile.open(fileobj=StringIO.StringIO(buf), mode="r:gz")

    folders = {
        os.path.join("modules", "signatures"): "signatures",
        os.path.join("data", "monitor"): "monitor",
        os.path.join("agent"): "agent",
    }

    members = t.getmembers()

    for tarfolder, outfolder in folders.items():
        mkdir(cwd(outfolder))

        # E.g., "community-master/modules/signatures".
        name_start = "%s/%s" % (members[0].name, tarfolder)
        for member in members:
            if not member.name.startswith(name_start) or \
                    name_start == member.name:
                continue

            filepath = cwd(outfolder, member.name[len(name_start)+1:])
            if member.isdir():
                mkdir(filepath)
                continue

            # TODO Ask for confirmation as we used to do.
            if os.path.exists(filepath) and not force:
                log.info(
                    "Not overwriting file which already exists: %s",
                    member.name
                )
                continue

            if member.issym():
                t.makelink(member, filepath)
                continue

            open(filepath, "wb").write(t.extractfile(member).read())

def enumerate_files(path, pattern):
    """Yields all filepaths from a directory."""
    if os.path.isfile(path):
        yield path
    elif os.path.isdir(path):
        for dirname, dirnames, filenames in os.walk(path):
            for filename in filenames:
                filepath = os.path.join(dirname, filename)

                if os.path.isfile(filepath):
                    if pattern:
                        if fnmatch.fnmatch(filename, pattern):
                            yield to_unicode(filepath)
                    else:
                        yield to_unicode(filepath)

def submit_tasks(target, options, package, custom, owner, timeout, priority,
                 machine, platform, memory, enforce_timeout, clock, tags,
                 remote, pattern, maxcount, is_url, is_baseline, is_shuffle):
    db = Database()

    data = dict(
        package=package,
        timeout=timeout,
        options=options,
        priority=priority,
        machine=machine,
        platform=platform,
        memory=memory,
        enforce_timeout=enforce_timeout,
        custom=custom,
        owner=owner,
        tags=tags,
    )

    if is_baseline:
        if remote:
            print "Remote baseline support has not yet been implemented."
            return

        task_id = db.add_baseline(timeout, owner, machine, memory)
        yield "Baseline", machine, task_id
        return

    if is_url:
        for url in target:
            if not remote:
                task_id = db.add_url(to_unicode(url), **data)
                yield "URL", url, task_id
                continue

            data["url"] = to_unicode(url)
            try:
                r = requests.post(
                    "http://%s/tasks/create/url" % remote, data=data
                )
                yield "URL", url, r.json()["task_id"]
            except Exception as e:
                print "%s: unable to submit URL: %s" % (
                    bold(red("Error")), e
                )
    else:
        files = []
        for path in target:
            files.extend(enumerate_files(path, pattern))

        for filepath in files:
            if not os.path.getsize(filepath):
                print "%s: sample %s (skipping file)" % (
                    bold(yellow("Empty")), filepath
                )
                continue

            if maxcount is not None:
                if not maxcount:
                    break
                maxcount -= 1

            if not remote:
                task_id = db.add_path(file_path=filepath, **data)
                yield "File", filepath, task_id
                continue

            files = {
                "file": (os.path.basename(filepath), open(filepath, "rb")),
            }

            try:
                r = requests.post(
                    "http://%s/tasks/create/file" % remote,
                    data=data, files=files
                )
                yield "File", filepath, r.json()["task_id"]
            except Exception as e:
                print "%s: unable to submit file: %s" % (
                    bold(red("Error")), e
                )
                continue
