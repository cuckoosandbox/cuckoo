# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import json
import zipfile
from StringIO import StringIO

from django.conf import settings

from bin.utils import json_default, get_directory_size
from bin.bytes2human import bytes2human
from controllers.analysis.analysis import AnalysisController

results_db = settings.MONGO

class ExportController:
    """Class for creating task exports"""

    def __init__(self):
        pass

    @staticmethod
    def estimate_size(task_id, taken_dirs, taken_files):
        report = AnalysisController.get_report(task_id)
        report = report['analysis']
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
            "size_human": bytes2human(size_estimated)
        }

    @staticmethod
    def create(task_id, taken_dirs, taken_files):
        """
        Returns a zip file as a file like object.
        :param task_id: task id
        :param taken_dirs: directories to include
        :param taken_files: files to include
        :return: zip file
        """

        if not taken_dirs and not taken_files:
            raise Exception("Please select at least one directory or file to be exported.")

        # @TO-DO: refactor
        taken_dirs_tmp = []
        for taken_dir in taken_dirs:
            if isinstance(taken_dir, tuple):
                taken_dirs_tmp.append(taken_dir[0])
            else:
                taken_dirs_tmp.append(taken_dir)

        taken_dirs = taken_dirs_tmp

        report = AnalysisController.get_report(task_id)
        report = report['analysis']

        if not report:
            raise Exception("The specified analysis does not exist")

        path = report["info"]["analysis_path"]

        # Creating an analysis.json file with basic information about this
        # analysis. This information serves as metadata when importing a task.
        analysis_path = os.path.join(path, "analysis.json")
        with open(analysis_path, "w") as outfile:
            report["target"].pop("file_id", None)
            metadata = {
                "info": report["info"],
                "target": report["target"],
            }
            json.dump(metadata, outfile, indent=4, default=json_default)

        f = StringIO()

        # Creates a zip file with the selected files and directories of the task.
        zf = zipfile.ZipFile(f, "w", zipfile.ZIP_DEFLATED)

        for dirname, subdirs, files in os.walk(path):
            if os.path.basename(dirname) == task_id:
                for filename in files:
                    if filename in taken_files:
                        zf.write(os.path.join(dirname, filename), filename)
            if os.path.basename(dirname) in taken_dirs:
                for filename in files:
                    zf.write(os.path.join(dirname, filename),
                             os.path.join(os.path.basename(dirname), filename))

        zf.close()

        return f

    @staticmethod
    def get_files(analysis_path):
        """Locate all directories/results available for this analysis"""

        dirs, files = [], []
        for filename in os.listdir(analysis_path):
            path = os.path.join(analysis_path, filename)
            if os.path.isdir(path):
                dirs.append((filename, len(os.listdir(path))))
            else:
                files.append(filename)

        return dirs, files