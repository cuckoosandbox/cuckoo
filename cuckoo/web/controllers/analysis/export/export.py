# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import io
import os
import json
import zipfile

from django.template.defaultfilters import filesizeformat

from cuckoo.common.utils import json_default
from cuckoo.web.controllers.analysis.analysis import AnalysisController
from cuckoo.web.utils import get_directory_size

class ExportController:
    """Class for creating task exports"""
    @staticmethod
    def estimate_size(task_id, taken_dirs, taken_files):
        report = AnalysisController.get_report(task_id)
        report = report["analysis"]
        path = report["info"]["analysis_path"]

        size_total = 0

        for directory in taken_dirs:
            destination = "%s/%s" % (path, directory)
            if os.path.isdir(destination):
                size_total += get_directory_size(destination)

        for filename in taken_files:
            destination = "%s/%s" % (path, filename)
            if os.path.isfile(destination):
                size_total += os.path.getsize(destination)

        # estimate file size after zipping; 60% compression rate typically
        size_estimated = size_total / 6.5

        return {
            "size": int(size_estimated),
            "size_human": filesizeformat(size_estimated)
        }

    @staticmethod
    def create(task_id, taken_dirs, taken_files, report=None):
        """
        Returns a zip file as a file like object.
        :param task_id: task id
        :param taken_dirs: directories to include
        :param taken_files: files to include
        :param report: additional report dict
        :return: zip file
        """
        if not taken_dirs and not taken_files:
            raise Exception(
                "Please select at least one directory or file to be exported."
            )

        # @TO-DO: refactor
        taken_dirs_tmp = []
        for taken_dir in taken_dirs:
            if isinstance(taken_dir, tuple):
                taken_dirs_tmp.append(taken_dir[0])
            else:
                taken_dirs_tmp.append(taken_dir)

        taken_dirs = taken_dirs_tmp

        if not report:
            report = AnalysisController.get_report(task_id)

        report = report["analysis"]
        path = report["info"]["analysis_path"]

        f = io.BytesIO()
        z = zipfile.ZipFile(f, "w", zipfile.ZIP_DEFLATED, allowZip64=True)

        for dirpath, dirnames, filenames in os.walk(path):
            if os.path.basename(dirpath) == task_id:
                for filename in filenames:
                    if filename in taken_files:
                        z.write(os.path.join(dirpath, filename), filename)
            if os.path.basename(dirpath) in taken_dirs:
                for filename in filenames:
                    z.write(
                        os.path.join(dirpath, filename),
                        os.path.join(os.path.basename(dirpath), filename)
                    )

        # Creating an analysis.json file with additional information about this
        # analysis. This information serves as metadata when importing a task.
        obj = {
            "action": report.get("debug", {}).get("action", []),
            "errors": report.get("debug", {}).get("errors", []),
        }
        z.writestr(
            "analysis.json", json.dumps(obj, indent=4, default=json_default)
        )

        z.close()
        return f

    @staticmethod
    def get_files(analysis_path):
        """Locate all directories/results available for this analysis"""
        if not os.path.exists(analysis_path):
            raise Exception("Analysis path not found: %s" % analysis_path)

        dirs, files = [], []
        for filename in os.listdir(analysis_path):
            path = os.path.join(analysis_path, filename)
            if os.path.isdir(path):
                dirs.append((filename, len(os.listdir(path))))
            else:
                files.append(filename)

        return dirs, files
