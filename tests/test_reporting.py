# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import responses
import tempfile

from cuckoo.common.files import Folders
from cuckoo.core.init import write_cuckoo_conf
from cuckoo.core.plugins import RunReporting
from cuckoo.main import cuckoo_create
from cuckoo.misc import set_cwd, cwd
from cuckoo.reporting.feedback import Feedback
from cuckoo.reporting.misp import MISP
from cuckoo.reporting.mongodb import MongoDB

def task(task_id, options, conf, results, filename="a.txt"):
    Folders.create(cwd(), ["conf", "storage"])
    Folders.create(cwd("storage"), ["analyses", "binaries"])
    Folders.create(cwd("storage", "analyses"), "%s" % task_id)
    Folders.create(cwd("storage", "analyses", "%s" % task_id), [
        "reports"
    ])

    write_cuckoo_conf({
        "reporting": conf,
    })

    task = {
        "id": task_id,
        "options": options,
        "target": filename,
    }
    RunReporting(task, results).run()

def test_empty_json():
    set_cwd(tempfile.mkdtemp())

    conf = {
        "jsondump": {
            "enabled": True,
        },
    }
    report_path = cwd("reports", "report.json", analysis=1)

    task(1, {}, conf, {})
    assert open(report_path, "rb").read() == "{}"

def test_unicode_json():
    set_cwd(tempfile.mkdtemp())

    conf = {
        "jsondump": {
            "enabled": True,
            "indent": 2,
        },
    }
    report_path = cwd("reports", "report.json", analysis=1)

    task(1, {}, conf, {
        "a": u"\u1234 \uecbc\uee9e",
    })
    assert open(report_path, "rb").read() == (
        '{\n  "a": "\\u1234 \\uecbc\\uee9e"\n}'
    )

def test_nonascii_json():
    set_cwd(tempfile.mkdtemp())

    conf = {
        "jsondump": {
            "enabled": True,
        },
    }
    report_path = cwd("reports", "report.json", analysis=1)

    task(1, {}, conf, {
        "a": "".join(chr(x) for x in range(256)),
    })
    buf = open(report_path, "rb").read()
    assert buf.startswith('{\n    "a": "\\u0000\\u0001\\u0002')
    assert buf.endswith('\\u00fd\\u00fe\\u00ff"\n}')

@responses.activate
def test_empty_mattermost():
    set_cwd(tempfile.mkdtemp())
    conf = {
        "mattermost": {
            "enabled": True,
            "url": "http://localhost/matter",
        },
    }
    responses.add(responses.POST, "http://localhost/matter")
    task(1, {}, conf, {})
    assert len(responses.calls) == 1

    # TODO Somehow catch the exception.
    conf["mattermost"]["url"] = "http://localhost/matter2"
    responses.add(responses.POST, "http://localhost/matter2", status=403)
    task(1, {}, conf, {})
    assert len(responses.calls) == 2

@responses.activate
def test_empty_misp():
    """Merely connects to MISP and creates the new event."""
    set_cwd(tempfile.mkdtemp())
    conf = {
        "misp": {
            "enabled": True,
            "url": "https://misphost",
            "apikey": "A"*32,
            "mode": "",
        },
    }

    with responses.RequestsMock(assert_all_requests_are_fired=True) as rsps:
        rsps.add(
            responses.GET, "https://misphost/servers/getVersion.json",
            json={
                "version": "2.4.56",
                "perm_sync": True,
            },
        )
        rsps.add(
            responses.GET, "https://misphost/attributes/describeTypes.json",
            json={
                "result": {
                    "categories": None,
                    "types": None,
                    "category_type_mappings": None,
                    "sane_defaults": True,
                },
            },
        )
        rsps.add(
            responses.POST, "https://misphost/events",
            json={
                "response": None,
            },
        )

        task(1, {}, conf, {})
        assert len(rsps.calls) == 3

def test_misp_sample_hashes():
    r = MISP()
    r.misp = mock.MagicMock()

    r.misp.add_hashes.return_value = None
    r.sample_hashes({
        "target": {
            "file": {
                "name": "foobar",
                "md5": "m d 5",
                "sha1": "sha one",
                "sha256": "sha 256",
            },
        },
    }, "event")
    r.misp.add_hashes.assert_called_once_with(
        "event", category="Payload delivery", filename="foobar",
        md5="m d 5", sha1="sha one", sha256="sha 256",
        comment="File submitted to Cuckoo"
    )

def test_misp_maldoc():
    r = MISP()
    r.misp = mock.MagicMock()
    r.misp.add_url.return_value = None

    r.maldoc_network({
        "signatures": [
            {
                "name": "foobar",
            },
            {
                "name": "malicious_document_urls",
                "marks": [
                    {
                        "category": "file",
                    },
                    {
                        "category": "url",
                        "ioc": "url_ioc",
                    }
                ],
            },
        ],
    }, "event")
    r.misp.add_url.assert_called_once_with("event", ["url_ioc"])

def test_misp_all_urls():
    r = MISP()
    r.misp = mock.MagicMock()
    r.misp.add_url.return_value = None

    r.all_urls({
        "network": {
            "http_ex": [
                {
                    "protocol": "http",
                    "host": "hello",
                    "uri": "/bar",
                },
            ],
            "https_ex": [
                {
                    "protocol": "https",
                    "host": "hello",
                    "uri": "/foobar",
                },
            ],
        },
    }, "event")
    r.misp.add_url.assert_called_once_with(
        "event", [
            "http://hello/bar", "https://hello/foobar"
        ]
    )

def test_misp_domain_ipaddr():
    r = MISP()
    r.misp = mock.MagicMock()
    r.misp.add_domains_ips.return_value = None
    r.misp.add_ipdst.return_value = None

    r.domain_ipaddr({
        "network": {
            "domains": [
                {
                    "domain": "foobar",
                    "ip": "1.2.3.4",
                },
                {
                    # TODO Now that we have global whitelisting, this
                    # custom-made support for the MISP reporting module should
                    # probably be removed.
                    "domain": "time.windows.com",
                    "ip": "1.2.3.4",
                },
            ],
            "hosts": [
                "2.3.4.5",
                "3.4.5.6",
            ],
        },
    }, "event")
    r.misp.add_domains_ips.assert_called_once_with(
        "event", {
            "foobar": "1.2.3.4",
        },
    )
    r.misp.add_ipdst.assert_called_once_with(
        "event", ["2.3.4.5", "3.4.5.6"],
    )

@mock.patch("cuckoo.reporting.mongodb.mongo")
def test_mongodb_init_once_new(p):
    p.init.return_value = True
    MongoDB().init_once()
    p.db.collection_names.return_value = []
    p.db.cuckoo_schema.save.assert_called_once_with({
        "version": "1",
    })
    p.db.fs.files.ensure_index.assert_called_once()

@mock.patch("cuckoo.reporting.mongodb.mongo")
def test_mongodb_init_once_new(p):
    p.init.return_value = True
    MongoDB().init_once()
    p.db.collection_names.return_value = []
    p.db.cuckoo_schema.save.assert_called_once_with({
        "version": "1",
    })
    p.db.fs.files.ensure_index.assert_called_once()

def test_feedback_empty():
    r = Feedback()
    r.set_path("tests/files/sample_analysis_storage")
    r.run({})

@mock.patch("cuckoo.reporting.feedback.CuckooFeedbackObject")
def test_feedback_not_enabled(p):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()

    r = Feedback()
    r.set_path("tests/files/sample_analysis_storage")
    r.run({
        "debug": {
            "errors": [
                "a", "b",
            ],
        },
    })
    p.assert_not_called()

@mock.patch("cuckoo.reporting.feedback.CuckooFeedbackObject")
@mock.patch("cuckoo.reporting.feedback.CuckooFeedback")
def test_feedback_enabled(p, q):
    set_cwd(tempfile.mkdtemp())
    cuckoo_create()

    r = Feedback()
    r.set_path("tests/files/sample_analysis_storage")
    r.run({
        "debug": {
            "errors": [
                "a", "b",
            ],
        },
    })
    q.assert_called_once()
    p.return_value.send_feedback.assert_called_once()
