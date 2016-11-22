# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path
import requests
import urlparse

from cuckoo.distributed.exception import InvalidReport, InvalidPcap

def _get(base, uri, *args, **kwargs):
    return requests.get(urlparse.urljoin(base, uri % args), **kwargs)

def list_machines(url):
    return _get(url, "/machines/list").json()["machines"]

def node_status(url):
    try:
        r = _get(url, "/cuckoo/status", timeout=120)
        return r.json()
    except:
        pass

def submit_task(url, task):
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
    try:
        r = requests.post(
            urlparse.urljoin(url, "/tasks/create/file"),
            data=data, files=files
        )
        return r.json()["task_id"]
    except Exception:
        pass

def fetch_tasks(url, status, limit):
    r = _get(url, "/tasks/list/%s", limit, params=dict(status=status))
    if r.status_code == 200:
        return r.json().get("tasks", [])
    return []

def store_report(url, task_id, report_format, dirpath):
    report = _get(
        url, "/tasks/report/%d/%s", task_id, report_format, stream=True
    )
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
    return _get(url, "/tasks/delete/%d", task_id).status_code == 200

def fetch_pcap(url, task_id, filepath):
    r = _get(url, "/pcap/get/%s", task_id, stream=True)
    if r is None or r.status_code != 200:
        raise InvalidPcap("No PCAP file found")

    with open(filepath, "wb") as f:
        for chunk in r.iter_content(chunk_size=1024*1024):
            f.write(chunk)
