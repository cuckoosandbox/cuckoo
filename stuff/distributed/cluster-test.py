# Copyright (C) 2017-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import click
import requests
import time

class Script(object):
    def __init__(self):
        self.name = self.__class__.__name__.lower()
        self.filename = "%s.py" % self.name
        self.source = self.__doc__

    def check(self):
        pass

class Internet(Script):
    r"""
import socket
s = socket.create_connection(("google.com", 80))
s.send("GET / HTTP/1.0\r\nHost: google.com\r\n\r\n")
s.recv(0x10000)
    """
    def check(self, report):
        for dns in report.get("network", {}).get("dns", []):
            if dns["request"] == "google.com" and dns["answers"]:
                return True
        return False

@click.command()
@click.argument("host")
@click.argument("port", default=9003, required=False)
@click.option("-s", "--script", default="internet")
def main(host, port, script):
    for cls in Script.__subclasses__():
        if cls().name == script:
            script = cls()
            break
    else:
        print "Unknown script:", script
        exit(1)

    owner = "cluster.test.%d" % int(time.time())
    url = "http://%s:%s" % (host, port)

    r = requests.get("%s/api/node" % url).json()

    machines = []
    for name, info in r["nodes"].items():
        if not info["enabled"]:
            continue

        print "indexing..", name
        info = requests.post("%s/api/node/%s/refresh" % (url, name)).json()
        for vm in info["machines"]:
            machines.append((name, vm["name"]))

    tasks = {}
    for node, vmname in machines:
        r = requests.post("%s/api/task" % url, files={
            "file": (script.filename, script.source),
        }, data={
            "node": node,
            "machine": vmname,
            "options": "json.calls=0",
            "priority": 5,
            "owner": owner,
        })
        tasks[r.json()["task_id"]] = node, vmname
        print "submitted..", node, vmname, r.json()["task_id"]

    status = []
    while tasks:
        r = requests.get("%s/api/task" % url, params={
            "status": "finished",
            "owner": owner,
        })
        assert r.status_code == 200

        for task in r.json()["tasks"].values():
            r = requests.get("%s/api/report/%d" % (url, task["id"]))
            if task["id"] not in tasks:
                continue
            node, vmname = tasks.pop(task["id"])
            ret = script.check(r.json())
            status.append((node, vmname, task["id"], ret))
            print "finished..", status[-1], "report.length=%d" % len(r.text)
            if not ret:
                print "^-- incorrect return value!"
            else:
                requests.delete("%s/api/task/%d" % (url, task["id"]))

        counts = {}
        for node, _ in tasks.values():
            counts[node] = counts.get(node, 0) + 1
        print "left:", " ".join("%s=%s" % (k, v) for k, v in counts.items())
        time.sleep(3)

if __name__ == "__main__":
    main()
