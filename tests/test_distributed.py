# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import requests
import responses
import tempfile

from cuckoo.distributed import api

def get(rsps, uri, **kwargs):
    rsps.add(responses.GET, "http://localhost" + uri, **kwargs)

def post(rsps, uri, **kwargs):
    rsps.add(responses.POST, "http://localhost" + uri, **kwargs)

@responses.activate
def test_cuckoo_api():
    """Test Distributed Cuckoo's interaction with the Cuckoo API."""
    with responses.RequestsMock(assert_all_requests_are_fired=True) as rsps:
        get(rsps, "/machines/list", json={"machines": "foo"})
        assert api.list_machines("http://localhost") == "foo"

        get(rsps, "/cuckoo/status", json={"a": "b"})
        assert api.node_status("http://localhost") == {"a": "b"}

        get(rsps, "/cuckoo/status", body="TIMEOUT", status=500)
        assert api.node_status("http://localhost") is None

        get(rsps, "/cuckoo/status", body=requests.ConnectionError("foo"))
        assert api.node_status("http://localhost") is None

        filepath = tempfile.mktemp()
        open(filepath, "wb").write("hello")

        d = {
            "filename": "bar.exe",
            "path": filepath,
            "package": None,
            "timeout": None,
            "priority": None,
            "options": None,
            "machine": None,
            "platform": None,
            "tags": None,
            "custom": None,
            "owner": None,
            "memory": None,
            "clock": None,
            "enforce_timeout": None,
        }

        post(rsps, "/tasks/create/file", json={"task_id": 12345})
        assert api.submit_task("http://localhost", d) == 12345

        post(rsps, "/tasks/create/file", body=requests.ConnectionError("a"))
        assert api.submit_task("http://localhost", d) is None

        get(rsps, "/tasks/list/100", json={"tasks": ["foo"]})
        assert api.fetch_tasks("http://localhost", "finished", 100) == ["foo"]

        get(rsps, "/tasks/report/1/json", body="A"*1024*1024*8)
        dirpath = tempfile.mkdtemp()
        r = api.store_report("http://localhost", 1, "json", dirpath)
        assert r == (1, "json")
        buf = open(os.path.join(dirpath, "report.json"), "rb").read()
        assert buf == "A"*1024*1024*8

        get(rsps, "/tasks/delete/42")
        assert api.delete_task("http://localhost", 42)

        get(rsps, "/pcap/get/123", body="A"*1024)
        filepath = tempfile.mktemp()
        assert api.fetch_pcap("http://localhost", 123, filepath) is None
        assert open(filepath, "rb").read() == "A"*1024
