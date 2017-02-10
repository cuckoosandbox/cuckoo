# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import mock
import os
import responses
import tempfile

from cuckoo.common.files import Folders, Files
from cuckoo.misc import cwd, set_cwd
from cuckoo.common.exceptions import CuckooFeedbackError

logging.basicConfig(level=logging.DEBUG)

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

CUCKOO_FEEDBACK_CONF_VALID = """
[feedback]
enabled = yes
name = Sander Ferdinand
email = sfer@cuckoo.sh
company = Cuckoo
"""

CUCKOO_FEEDBACK_CONF_MISSING_NAME = """
[feedback]
enabled = yes
name =
email = sfer@cuckoo.sh
company = Cuckoo
"""

CUCKOO_FEEDBACK_CONF_MISSING_EMAIL = """
[feedback]
enabled = yes
name = Sander Ferdinand
company = Cuckoo
"""

CUCKOO_FEEDBACK_CONF_FAULTY_EMAIL = """
[feedback]
enabled = yes
name = Sander Ferdinand
email = sfer@cuckoo,sh
company = Cuckoo
"""

from cuckoo.web.web.errors import ExceptionMiddleware
from django.utils import unittest
from django.test.client import RequestFactory

class TestFeedback(unittest.TestCase):
    def setUp(self):
        self.dirpath = tempfile.mkdtemp()
        set_cwd(self.dirpath)
        Folders.create(cwd(), ["conf", "web"])

        Files.create(cwd(), "conf/reporting.conf", REPORTING_CONF)
        Files.create(cwd(), "conf/routing.conf", ROUTING_CONF)
        Files.create(cwd(), "web/.secret_key", "A" * 40)
        Files.create(cwd(), "web/local_settings.py", "")

        os.environ["CUCKOO_APP"] = "web"
        os.environ["CUCKOO_CWD"] = cwd()

        self.analysis_path = "%s/storage/analysis/1/" % cwd()
        self.analysis_id = 1
        Folders.copy("tests/files/sample_analysis_storage",
                     self.analysis_path)

        data = {'task_id': str(self.analysis_id)}
        self.factory = RequestFactory()
        self.request = self.factory.get('/analysis/%d/summary' %
                                        self.analysis_id, data=data)

    def test_exception_middleware(self):
        em = ExceptionMiddleware()
        assert em.process_exception(self.request, Exception) is None

    def test_send_exception_valid_conf(self):
        """tests CuckooFeedback.send_exception with a valid feedback config"""
        Files.create(self.dirpath, "conf/cuckoo.conf",
                     CUCKOO_CONF+CUCKOO_FEEDBACK_CONF_VALID)

        from cuckoo.core.feedback import CuckooFeedback
        with responses.RequestsMock(assert_all_requests_are_fired=True) as rsps:
            with mock.patch("cuckoo.web.controllers.analysis.analysis.AnalysisController") as ac:
                ac._get_report.return_value = self._report(self.analysis_path)

                feedback = CuckooFeedback()
                rsps.add(responses.POST, feedback.endpoint,
                         json={"status": True, "feedback_id": 1}, status=200)

                ex = Exception("Mock Exception")
                feedback_id = feedback.send_exception(ex, self.request)
                assert feedback_id == 1

        self._teardown()

    def test_send_exception_faulty_feedback_config(self):
        """tests CuckooFeedback.send_exception with missing/faulty feedback configurations"""
        config_cases = {
            "missing_name": CUCKOO_CONF+CUCKOO_FEEDBACK_CONF_MISSING_NAME,
            "missing_email": CUCKOO_CONF+CUCKOO_FEEDBACK_CONF_MISSING_EMAIL,
            "faulty_email": CUCKOO_CONF+CUCKOO_FEEDBACK_CONF_FAULTY_EMAIL,
            "no_config": CUCKOO_CONF
        }

        config_path = "conf/cuckoo.conf"

        for test_case, config_contents in config_cases.iteritems():
            if os.path.isfile(config_path):
                os.remove(config_path)
            Files.create(self.dirpath, config_path, config_contents)

            from cuckoo.core.feedback import CuckooFeedback
            with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
                with mock.patch("cuckoo.web.controllers.analysis.analysis.AnalysisController") as ac:
                    ac._get_report.return_value = self._report(self.analysis_path)

                    feedback = CuckooFeedback()
                    rsps.add(responses.POST, feedback.endpoint,
                             json={"status": True, "feedback_id": 1}, status=200)

                    ex = Exception("Mock Exception")
                    self.assertRaises(CuckooFeedbackError,
                                      feedback.send_exception, ex, self.request)
        self._teardown()

    def test_send_exception_faulty_endpoint(self):
        """tests CuckooFeedback.send_exception with a valid feedback config and faulty endpoint"""
        Files.create(self.dirpath, "conf/cuckoo.conf",
                     CUCKOO_CONF+CUCKOO_FEEDBACK_CONF_VALID)

        from cuckoo.core.feedback import CuckooFeedback
        with responses.RequestsMock(assert_all_requests_are_fired=True) as rsps:
            with mock.patch("cuckoo.web.controllers.analysis.analysis.AnalysisController") as ac:
                ac._get_report.return_value = self._report(self.analysis_path)

                feedback = CuckooFeedback()
                rsps.add(responses.POST, feedback.endpoint,
                         json={"status": False, "message": "BIEM"}, status=500)

                ex = Exception("Mock Exception")
                self.assertRaises(CuckooFeedbackError, feedback.send_exception, ex, self.request)
        self._teardown()

    def test_feedback_include_report(self):
        """tests CuckooFeedback.include_report with an URL and file analysis report"""
        # @TODO: implement file reports

        Files.create(self.dirpath, "conf/cuckoo.conf",
                     CUCKOO_CONF+CUCKOO_FEEDBACK_CONF_VALID)

        from cuckoo.core.feedback import CuckooFeedbackObject
        with mock.patch("cuckoo.web.controllers.analysis.analysis.AnalysisController") as ac:
            ac._get_report.return_value = self._report(self.analysis_path)

            feedback = CuckooFeedbackObject()
            feedback.include_report(self.analysis_id)

            assert feedback.report_info["analysis_id"] == 1
            assert feedback.report_info["file"]["task_id"] == 1
            assert feedback.report_info["file"]["name"] == "binary"
            assert feedback.report_info["file"]["size"] == 91010
        self._teardown()

    def test_feedback_include_analysis(self):
        """tests CuckooFeedback.include_analysis"""

        Files.create(self.dirpath, "conf/cuckoo.conf",
                     CUCKOO_CONF+CUCKOO_FEEDBACK_CONF_VALID)

        from cuckoo.core.feedback import CuckooFeedbackObject
        with mock.patch("cuckoo.web.controllers.analysis.analysis.AnalysisController") as ac:
            ac._get_report.return_value = self._report(self.analysis_path)

            feedback = CuckooFeedbackObject()
            feedback.include_report(self.analysis_id)
            feedback.include_analysis(include_memdump=True)

            assert len(feedback.export) > 200000
        self._teardown()

    def test_feedback_append_error(self):
        """tests CuckooFeedbackObject.add_error"""
        Files.create(self.dirpath, "conf/cuckoo.conf",
                     CUCKOO_CONF+CUCKOO_FEEDBACK_CONF_VALID)

        from cuckoo.core.feedback import CuckooFeedbackObject
        feedback = CuckooFeedbackObject(message="test")
        feedback.add_error("test")

        assert feedback.errors[0] == "test"
        self._teardown()

    def test_send(self):
        """tests CuckooFeedback.send_exception with a valid feedback config"""
        Files.create(self.dirpath, "conf/cuckoo.conf",
                     CUCKOO_CONF+CUCKOO_FEEDBACK_CONF_VALID)

        from cuckoo.core.feedback import CuckooFeedback
        with responses.RequestsMock(assert_all_requests_are_fired=True) as rsps:
            with mock.patch("cuckoo.web.controllers.analysis.analysis.AnalysisController") as ac:
                ac._get_report.return_value = self._report(self.analysis_path)

                feedback = CuckooFeedback()
                rsps.add(responses.POST, feedback.endpoint,
                         json={"status": True, "feedback_id": 1}, status=200)

                feedback_id = feedback.send(
                    self.analysis_id, "TestName", "test@email.com", "TestMessage",
                    "TestCompany", True, True, True, False)
                assert feedback_id == 1
        self._teardown()

    def _teardown(self):
        Folders.delete(self.analysis_path)

    def _report(self, analysis_path):
        return {
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
                "analysis_path": analysis_path
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
