# Copyright (C) 2016-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import os
import pytest
import responses
import tempfile
import zipfile

from cuckoo.common.exceptions import CuckooFeedbackError
from cuckoo.core.feedback import CuckooFeedback, CuckooFeedbackObject
from cuckoo.main import cuckoo_create
from cuckoo.misc import cwd, set_cwd
from cuckoo.web.web.errors import ExceptionMiddleware

class TestFeedback(object):
    def setup(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "cuckoo": {
                "feedback": {
                    "enabled": True,
                    "name": "foo bar",
                    "email": "foo@bar.com",
                    "company": "Cuckoo",
                },
            },
        })

        os.environ["CUCKOO_APP"] = "web"
        os.environ["CUCKOO_CWD"] = cwd()

    @responses.activate
    def test_exception_middleware(self, rf):
        feedback = CuckooFeedback()
        responses.add(
            responses.POST, feedback.endpoint, json={
                "status": True,
                "feedback_id": 0,
            }, status=200
        )

        try:
            raise Exception("This is an exception!")
        except Exception as e:
            em = ExceptionMiddleware()
            assert em.process_exception(
                rf.get("/analysis/1/summary"), e
            ) is None

    @responses.activate
    def test_exception_no_analysis(self):
        feedback = CuckooFeedback()
        responses.add(
            responses.POST, feedback.endpoint, json={
                "status": True,
                "feedback_id": 1,
            }, status=200
        )

        assert feedback.send_exception(
            Exception("Mock Exception"), None
        ) == 1

    def test_invalid_configuration(self):
        # Explicitly want a clean CWD here.
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()

        cf = CuckooFeedback()

        with pytest.raises(CuckooFeedbackError) as e:
            cf.send_feedback(CuckooFeedbackObject(
                name=None, email="a@b.com", company="foo"
            ))
        e.match("Could not validate")

        with pytest.raises(CuckooFeedbackError) as e:
            cf.send_feedback(CuckooFeedbackObject(
                name="foo", email=None, company="foo"
            ))
        e.match("Could not validate")

        with pytest.raises(CuckooFeedbackError) as e:
            cf.send_feedback(CuckooFeedbackObject(
                name="foo", email="a@b,com", company="foo"
            ))
        e.match("Could not validate")

        with pytest.raises(CuckooFeedbackError) as e:
            cf.send_feedback(CuckooFeedbackObject(
                name="foo", email="a@b.com", company=None
            ))
        e.match("Could not validate")

    def test_append_error(self):
        feedback = CuckooFeedbackObject(message="test")
        feedback.add_error("test")

        obj = feedback.to_dict()
        assert obj["message"] == "test"
        assert obj["errors"] == ["test"]

    @mock.patch("cuckoo.web.controllers.analysis.analysis.AnalysisController")
    @mock.patch("cuckoo.core.feedback.CuckooFeedbackObject")
    def test_include_404_report(self, p, q):
        class request(object):
            method = "GET"

            class resolver_match(object):
                kwargs = {
                    "task_id": 1,
                }

        q._get_report.return_value = {}
        p.return_value.report = None
        p.return_value.validate.side_effect = CuckooFeedbackError

        with pytest.raises(CuckooFeedbackError):
            feedback = CuckooFeedback()
            feedback.send_exception(Exception, request)

        p.return_value.include_report_web.assert_called_once()
        p.return_value.include_analysis.assert_not_called()

    def report(self, analysis_path):
        return {
            "info": {
                "id": 1,
                "analysis_path": analysis_path
            },
            "target": {
                "category": "file",
                "file": {
                    "name": "binary",
                    "size": 91010,
                }
            }
        }
