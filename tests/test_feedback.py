# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import django
import logging
import mock
import os
import tempfile
from mock import Mock

from cuckoo.core.database import Database
from cuckoo.common.files import Folders, Files
from cuckoo.misc import cwd, set_cwd
from cuckoo.processing.static import Static

logging.basicConfig(level=logging.DEBUG)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")

CUCKOO_CONF = """
[cuckoo]
tmppath = /tmp

[database]
connection =
"""

REPORTING_CONF = """
[mongodb]
enabled = on
[elasticsearch]
enabled = off
[moloch]
enabled = off
"""

ROUTING_CONF = """
[routing]
route = none
internet = none
drop = off
[inetsim]
enabled = off
[tor]
enabled = off
[vpn]
enabled = off
"""

FEEDBACK_CONF_VALID = """
[feedback]
enabled = yes
name = Sander Ferdinand
email =
company = Cuckoo
endpoint = https://cuckoo.sh/feedback/api/submit/
"""

CONF_MISSING_NAME = """
[cuckoo]
tmppath = /tmp

[database]
connection =

[feedback]
enabled = yes
name =
email = sfer@cuckoo.sh
company = Cuckoo
endpoint = https://cuckoo.sh/feedback/api/submit/
"""

CONF_MISSING_COMPANY = """
[cuckoo]
tmppath = /tmp

[database]
connection =

[feedback]
enabled = yes
name = Sander Ferdinand
email = sfer@cuckoo.sh
company =
endpoint = https://cuckoo.sh/feedback/api/submit/
"""

CONF_MISSING_ENDPOINT = """
[cuckoo]
tmppath = /tmp

[database]
connection =

[feedback]
enabled = yes
name = Sander Ferdinand
email = sfer@cuckoo.sh
company = Cuckoo
endpoint =
"""

from cuckoo.web.web.errors import ExceptionMiddleware
from django.utils import unittest
from django.test.client import RequestFactory

class TestFeedback(unittest.TestCase):
    def setUp(self):
        self.dirpath = tempfile.mkdtemp()
        set_cwd(self.dirpath)
        a = cwd()
        Folders.create(a, ["conf", "web"])

        Files.create(cwd(), "conf/cuckoo.conf", CUCKOO_CONF)
        Files.create(cwd(), "conf/reporting.conf", REPORTING_CONF)
        Files.create(cwd(), "conf/routing.conf", ROUTING_CONF)
        Files.create(cwd(), "web/.secret_key", "A" * 40)
        Files.create(cwd(), "web/local_settings.py", "")

        os.environ["CUCKOO_APP"] = "web"
        os.environ["CUCKOO_CWD"] = cwd()

        self.factory = RequestFactory()

    # def test_exception_middleware(self):
    #     em = ExceptionMiddleware()
    #     assert em.process_exception(self.request, Exception) is None

    def test_send_exception(self):
        os.remove("%s/conf/cuckoo.conf" % self.dirpath)
        Files.create(self.dirpath, "conf/cuckoo.conf", CUCKOO_CONF+FEEDBACK_CONF_VALID)

        # django.setup()
        # Database().connect()

        data = {'task_id': '1'}
        request = self.factory.get('/analysis/11/summary', data=data)

        from cuckoo.core.feedback import CuckooFeedback


        with mock.patch("controllers.analysis.analysis.AnalysisController") as ac:
            #with mock.patch("controllers.analysis.export.export.ExportController") as ec:
                #ec.get_files.return_value = {"l;ol": "e"}

            ac._get_report.return_value = {
                "static": {
                    "office": {
                        "macros": [
                            {
                                "filename": "MACRO FILENAME",
                                "stream": "MACRO STREAM",
                                "orig_code": "MACRO CODE OBFUSCATED",
                                "deobf": "MACRO CODE DEOBFUSCATED",
                            },
                        ],
                    },
                },
                "info": {
                    "id": 1,
                    "analysis_path": "/home/test/.cuckoo/storage/analyses/1"
                },
                "target": {
                    "category": "file",
                    "file": {
                        "crc32": "D41D8910",
                        "md5": "86730a9bc3ab99503322eda6115c1096",
                        "name": "binary",
                        "path": "/home/dsc/.cuckoo/storage/analyses/11/binary",
                        "sha1": "dc1fc6805a645f12f6864ff9d6f5096a09dbec6c",
                        "sha256": "8a2b54f64d1866ac8c46c99651cadba1597bc5671cf9b4a966c1d23898b19ce6",
                        "sha512": "9452152edc69b346a19c2dee3b8b4b4a4ba75e8abad631196ce0519b9308d4012e2c7a4418cd852b0830b3265761f86638136d26592421c0cc599396efa50ae0",
                        "size": 91010,
                        "ssdeep": None,
                        "type": "PDF document, version 1.7",
                        "urls": [
                            "http://ns.adobe.com/pdf/1.3/",
                            "http://purl.org/dc/elements/1.1/",
                            "http://ns.adobe.com/xap/1.0/mm/",
                            "http://ns.adobe.com/xap/1.0/"
                        ],
                        "yara": []
                    }
                }
            }

            ex = Exception("Test Exception")
            CuckooFeedback().send_exception(ex, request)