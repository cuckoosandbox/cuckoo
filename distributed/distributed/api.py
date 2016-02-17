# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path
import shutil
import requests

from distributed.exception import InvalidReport

def list_machines(url):
    r = requests.get(os.path.join(url, "machines", "list"))
    return r.json()["machines"]

def node_status(url):
    try:
        r = requests.get(os.path.join(url, "cuckoo", "status"), timeout=120)
        return r.json()
    except:
        pass

def submit_task(url, task):
    url = os.path.join(url, "tasks", "create", "file")
    data = dict(
        package=task["package"],
        timeout=task["timeout"],
        priority=task["priority"],
        options=task["options"],
        machine=task["machine"],
        platform=task["platform"],
        tags=task["tags"],
        custom=task["custom"],
        owner=task["owner"],
        memory=task["memory"],
        clock=task["clock"],
        enforce_timeout=task["enforce_timeout"],
    )

    # If the file does not exist anymore, ignore it and move on
    # to the next file.
    if not os.path.isfile(task["path"]):
        return task["id"], None

    files = {"file": (task["filename"], open(task["path"], "rb"))}
    r = requests.post(url, data=data, files=files)
    return r.json()["task_id"]

def fetch_tasks(url, status):
    url = os.path.join(url, "tasks", "list")
    r = requests.get(url, params=dict(status=status))
    return r.json()["tasks"]

def store_report(url, task_id, report_format, dirpath):
    url = os.path.join(url, "tasks", "report", "%d" % task_id, report_format)
    report = requests.get(url, stream=True)
    if report is None:
        raise InvalidReport("Report is none..")

    if report.status_code != 200:
        raise InvalidReport("Report status code %d" % report.status_code)

    path = os.path.join(dirpath, "report.%s" % report_format)
    with open(path, "wb") as f:
        for chunk in report.iter_content(chunk_size=1024*1024):
            f.write(chunk)

    return task_id, report_format

def delete_task(url, task_id):
    url = os.path.join(url, "tasks", "delete", "%d" % task_id)
    return requests.get(url).status_code == 200

def fetch_pcap(url, task_id, filepath):
    url = os.path.join(url, "pcap", "get", "%s" % task_id)
    # Explicitly disable any compression as otherwise we'd end up with a
    # compressed file as shutil.copyfileobj() wouldn't decompress it
    # transparently.
    headers = {
        "accept-encoding": "gzip;q=0,deflate,sdch",
    }
    r = requests.get(url, headers=headers, stream=True)
    with open(filepath, "wb") as f:
        shutil.copyfileobj(r.raw, f)
