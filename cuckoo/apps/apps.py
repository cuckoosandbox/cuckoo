# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import datetime
import fnmatch
import hashlib
import io
import logging
import os.path
import pymongo
import random
import requests
import shutil
import subprocess
import sys
import tarfile
import time

from cuckoo.common.colors import bold, red, yellow
from cuckoo.common.config import config, emit_options, Config
from cuckoo.common.elastic import elastic
from cuckoo.common.exceptions import (
    CuckooOperationalError, CuckooDatabaseError, CuckooDependencyError
)
from cuckoo.common.objects import Dictionary, File
from cuckoo.common.utils import to_unicode
from cuckoo.core.database import (
    Database, TASK_FAILED_PROCESSING, TASK_REPORTED
)
from cuckoo.core.init import write_cuckoo_conf
from cuckoo.core.log import task_log_start, task_log_stop, logger
from cuckoo.core.plugins import RunProcessing, RunSignatures, RunReporting
from cuckoo.core.startup import init_console_logging
from cuckoo.misc import cwd, mkdir

log = logging.getLogger(__name__)

URL = "https://github.com/cuckoosandbox/community/archive/%s.tar.gz"

def fetch_community(branch="master", force=False, filepath=None):
    if filepath:
        buf = open(filepath, "rb").read()
    else:
        log.info("Downloading.. %s", URL % branch)
        r = requests.get(URL % branch)
        if r.status_code != 200:
            raise CuckooOperationalError(
                "Error fetching the Cuckoo Community binaries "
                "(status_code: %d)!" % r.status_code
            )

        buf = r.content

    t = tarfile.TarFile.open(fileobj=io.BytesIO(buf), mode="r:gz")

    folders = {
        "modules/signatures": "signatures",
        "data/monitor": "monitor",
        "data/yara": "yara",
        "agent": "agent",
        "analyzer": "analyzer",
    }

    members = t.getmembers()

    directory = members[0].name.split("/")[0]
    for tarfolder, outfolder in folders.items():
        mkdir(cwd(outfolder))

        # E.g., "community-master/modules/signatures".
        name_start = "%s/%s" % (directory, tarfolder)
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
                log.debug(
                    "Not overwriting file which already exists: %s",
                    member.name[len(name_start)+1:]
                )
                continue

            if member.issym():
                t.makelink(member, filepath)
                continue

            if not os.path.exists(os.path.dirname(filepath)):
                os.makedirs(os.path.dirname(filepath))

            log.debug("Extracted %s..", member.name[len(name_start)+1:])
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
                 remote, pattern, maxcount, is_unique, is_url, is_baseline,
                 is_shuffle):
    db = Database()

    data = dict(
        package=package or "",
        timeout=timeout,
        options=options,
        priority=priority,
        machine=machine,
        platform=platform,
        custom=custom,
        owner=owner,
        tags=tags,
        memory="1" if memory else "0",
        enforce_timeout="1" if enforce_timeout else "0",
        clock=clock,
        unique="1" if is_unique else "0",
    )

    if is_baseline:
        if remote:
            print "Remote baseline support has not yet been implemented."
            return

        task_id = db.add_baseline(timeout, owner, machine, memory)
        yield "Baseline", machine, task_id
        return

    if is_url and is_unique:
        print "URL doesn't have --unique support yet."
        return

    if is_url:
        for url in target:
            if not remote:
                data.pop("unique", None)
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
            files.extend(enumerate_files(os.path.abspath(path), pattern))

        if is_shuffle:
            random.shuffle(files)

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
                if is_unique:
                    sha256 = File(filepath).get_sha256()
                    if db.find_sample(sha256=sha256):
                        yield "File", filepath, None
                        continue

                data.pop("unique", None)
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

def process(target, copy_path, task):
    results = RunProcessing(task=task).run()
    RunSignatures(results=results).run()
    RunReporting(task=task, results=results).run()

    if config("cuckoo:cuckoo:delete_original"):
        try:
            if target and os.path.exists(target):
                os.remove(target)
        except OSError as e:
            log.error(
                "Unable to delete original file at path \"%s\": %s",
                target, e
            )

    if config("cuckoo:cuckoo:delete_bin_copy"):
        try:
            if copy_path and os.path.exists(copy_path):
                os.remove(copy_path)
        except OSError as e:
            log.error(
                "Unable to delete the copy of the original file at "
                "path \"%s\": %s", copy_path, e
            )

def process_task(task):
    db = Database()

    try:
        task_log_start(task["id"])

        logger(
            "Starting task reporting",
            action="task.report", status="pending",
            target=task["target"], category=task["category"],
            package=task["package"], options=emit_options(task["options"]),
            custom=task["custom"]
        )

        if task["category"] == "file" and task.get("sample_id"):
            sample = db.view_sample(task["sample_id"])
            copy_path = cwd("storage", "binaries", sample.sha256)
        else:
            copy_path = None

        try:
            process(task["target"], copy_path, task)
            db.set_status(task["id"], TASK_REPORTED)
        except Exception as e:
            log.exception("Task #%d: error reporting: %s", task["id"], e)
            db.set_status(task["id"], TASK_FAILED_PROCESSING)

        log.info("Task #%d: reports generation completed", task["id"], extra={
            "action": "task.report", "status": "success",
        })
    except Exception as e:
        log.exception("Caught unknown exception: %s", e)
    finally:
        task_log_stop(task["id"])

def process_task_range(tasks):
    db, task_ids = Database(), []
    for entry in tasks.split(","):
        if entry.isdigit():
            task_ids.append(int(entry))
        elif entry.count("-") == 1:
            start, end = entry.split("-")
            if not start.isdigit() or not end.isdigit():
                log.warning("Invalid range provided: %s", entry)
                continue
            task_ids.extend(range(int(start), int(end)+1))
        elif entry:
            log.warning("Invalid range provided: %s", entry)

    for task_id in sorted(set(task_ids)):
        task = db.view_task(task_id)
        if not task:
            task = {
                "id": task_id,
                "category": "file",
                "target": "",
                "options": {},
                "package": None,
                "custom": None,
            }
        else:
            task = task.to_dict()

        if os.path.isdir(cwd(analysis=task_id)):
            process_task(Dictionary(task))

def process_tasks(instance, maxcount):
    count = 0
    db = Database()

    try:
        while not maxcount or count != maxcount:
            task_id = db.processing_get_task(instance)

            # Wait a small while before trying to fetch a new task.
            if task_id is None:
                time.sleep(1)
                continue

            task = db.view_task(task_id)

            log.info("Task #%d: reporting task", task.id)

            process_task(task.to_dict())
            count += 1
    except Exception as e:
        log.exception("Caught unknown exception: %s", e)

def cuckoo_clean():
    """Clean up cuckoo setup.
    It deletes logs, all stored data from file system and configured
    databases (SQL and MongoDB).
    """
    # Init logging (without writing to file).
    init_console_logging()

    try:
        # Initialize the database connection.
        db = Database()
        db.connect(schema_check=False)

        # Drop all tables.
        db.drop()
    except (CuckooDependencyError, CuckooDatabaseError) as e:
        # If something is screwed due to incorrect database migrations or bad
        # database SqlAlchemy would be unable to connect and operate.
        log.warning("Error connecting to database: it is suggested to check "
                    "the connectivity, apply all migrations if needed or purge "
                    "it manually. Error description: %s", e)

    # Check if MongoDB reporting is enabled and drop that if it is.
    # TODO Move to the MongoDB abstract.
    if config("reporting:mongodb:enabled"):
        host = config("reporting:mongodb:host")
        port = config("reporting:mongodb:port")
        mdb = config("reporting:mongodb:db")
        try:
            conn = pymongo.MongoClient(host, port)
            conn.drop_database(mdb)
            conn.close()
        except:
            log.warning("Unable to drop MongoDB database: %s", mdb)

    # Check if ElasticSearch reporting is enabled and drop its data if it is.
    if elastic.init():
        elastic.connect()

        # TODO This should be moved to the elastic abstract.
        # TODO We should also drop historic data, i.e., from pervious days,
        # months, and years.
        date_index = datetime.datetime.utcnow().strftime({
            "yearly": "%Y",
            "monthly": "%Y-%m",
            "daily": "%Y-%m-%d",
        }[elastic.index_time_pattern])
        dated_index = "%s-%s" % (elastic.index, date_index)

        elastic.client.indices.delete(
            index=dated_index, ignore=[400, 404]
        )

        template_name = "%s_template" % dated_index
        if elastic.client.indices.exists_template(template_name):
            elastic.client.indices.delete_template(template_name)

    # Paths to clean.
    paths = [
        cwd("cuckoo.db"),
        cwd("log"),
        cwd("storage", "analyses"),
        cwd("storage", "baseline"),
        cwd("storage", "binaries"),
    ]

    # Delete the various files and directories. In case of directories, keep
    # the parent directories, so to keep the state of the CWD in tact.
    for path in paths:
        if os.path.isdir(path):
            try:
                shutil.rmtree(path)
                os.mkdir(path)
            except (IOError, OSError) as e:
                log.warning("Error removing directory %s: %s", path, e)
        elif os.path.isfile(path):
            try:
                os.unlink(path)
            except (IOError, OSError) as e:
                log.warning("Error removing file %s: %s", path, e)

def cuckoo_machine(vmname, action, ip, platform, options, tags,
                   interface, snapshot, resultserver):
    db = Database()

    cfg = Config.from_confdir(cwd("conf"))
    machinery = cfg["cuckoo"]["cuckoo"]["machinery"]
    machines = cfg[machinery][machinery]["machines"]

    if action == "add":
        if not ip:
            sys.exit("You have to specify a legitimate IP address for --add.")

        if db.view_machine(vmname):
            sys.exit("A Virtual Machine with this name already exists!")

        if vmname in machines:
            sys.exit("A Virtual Machine with this name already exists!")

        if resultserver and resultserver.count(":") == 1:
            resultserver_ip, resultserver_port = resultserver.split(":")
            resultserver_port = int(resultserver_port)
        else:
            resultserver_ip = cfg["cuckoo"]["resultserver"]["ip"]
            resultserver_port = cfg["cuckoo"]["resultserver"]["port"]

        machines.append(vmname)
        cfg[machinery][vmname] = {
            "label": vmname,
            "platform": platform,
            "ip": ip,
            "options": options,
            "snapshot": snapshot,
            "interface": interface,
            "resultserver_ip": resultserver_ip,
            "resultserver_port": resultserver_port,
            "tags": tags,
        }

        db.add_machine(
            vmname, vmname, ip, platform, options, tags, interface, snapshot,
            resultserver_ip, int(resultserver_port)
        )
        db.unlock_machine(vmname)

    if action == "delete":
        # TODO Add a db.del_machine() function for runtime modification.

        if vmname not in machines:
            sys.exit("A Virtual Machine with this name doesn't exist!")

        machines.remove(vmname)
        cfg[machinery].pop(vmname)

    write_cuckoo_conf(cfg=cfg)

def migrate_database(revision="head"):
    args = [
        "alembic", "-x", "cwd=%s" % cwd(), "upgrade", revision,
    ]
    try:
        subprocess.check_call(args, cwd=cwd("db_migration", private=True))
    except subprocess.CalledProcessError:
        return False
    return True

def migrate_cwd():
    log.warning(
        "This is the first time you're running Cuckoo after updating your "
        "local version of Cuckoo. We're going to update files in your CWD "
        "that require updating. Note that we'll first ensure that no custom "
        "patches have been applied by you before applying any modifications "
        "of our own."
    )

    # Migration from 2.0.2 to 2.0.3. TODO Abstract this away.
    if not os.path.exists(cwd("yara", "index_scripts.yar")):
        open(cwd("yara", "index_scripts.yar"), "wb").close()

    if not os.path.exists(cwd("yara", "index_shellcode.yar")):
        open(cwd("yara", "index_shellcode.yar"), "wb").close()

    hashes = {}
    for line in open(cwd("cwd", "hashes.txt", private=True), "rb"):
        if not line.strip() or line.startswith("#"):
            continue
        hash_, filename = line.split()
        hashes[filename] = hashes.get(filename, []) + [hash_]

    modified, outdated = [], []
    for filename, hashes in hashes.items():
        if not os.path.exists(cwd(filename)):
            outdated.append(filename)
            continue
        hash_ = hashlib.sha1(open(cwd(filename), "rb").read()).hexdigest()
        if hash_ not in hashes:
            modified.append(filename)
        if hash_ != hashes[-1]:
            outdated.append(filename)

    if modified:
        log.error(
            "One or more files in the CWD have been modified outside of "
            "regular Cuckoo usage. Due to these changes Cuckoo isn't able to "
            "automatically upgrade your setup."
        )

        for filename in sorted(modified):
            log.warning("Modified file: %s (=> %s)", filename, cwd(filename))

        log.error("Moving forward you have two options:")
        log.warning(
            "1) You make a backup of the affected files, remove their "
            "presence in the CWD (yes, actually 'rm -f' the file), and "
            "re-run Cuckoo to automatically restore the new version of the "
            "file. Afterwards you'll be able to re-apply any changes as you "
            "like."
        )
        log.warning(
            "2) You revert back to the version of Cuckoo you were on "
            "previously and accept that manual changes that have not been "
            "merged upstream require additional maintenance that you'll "
            "pick up at a later point in time."
        )

        sys.exit(1)

    for filename in outdated:
        log.debug("Upgraded %s", filename)
        if not os.path.exists(os.path.dirname(cwd(filename))):
            os.makedirs(os.path.dirname(cwd(filename)))
        shutil.copy(cwd("..", "data", filename, private=True), cwd(filename))

    log.info(
        "Automated migration of your CWD was successful! Continuing "
        "execution of Cuckoo as expected."
    )
