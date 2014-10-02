# -*- coding: utf-8 -*-
# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
from subprocess import Popen

from lib.api.process import Process
from lib.common.abstracts import Package
from lib.common.results import upload_to_host
from lib.common.exceptions import CuckooPackageError

log = logging.getLogger()


class Tool(Package):
    """Tool analysis package.

    Runs a tool on the sample
    """

    temp_dir = ""
    tool_dir = ""
    tool_name = ""
    tool_process = None
    log_file_name = "tool_output.log"
    log_file_path = ""
    orig_files = []

    def space_buffer(self, string):
        return " " + string + " "

    def format_user_options(self, options, sample_options, path):
        options = self.space_buffer(options)
        if "$sample" in options:
            options = options.replace("$sample", path)
        else:
            options = options + path

        sample_options = self.space_buffer(sample_options)
        if "$sample_options" in options:
            options = options.replace("$sample_options", sample_options)
        else:
            options = options + sample_options

        return options

    def get_tool_name(self):
        """Removes the .tool extension from the tool
        and makes the necessary changes to orig_files list
        """
        tool_name = ""
        count = 0
        for fyle in os.listdir(self.tool_dir):
            if fyle[-5:].lower() == ".tool":
                self.orig_files.remove(fyle)
                tool_name = fyle[:-5]

                if tool_name in self.orig_files:
                    os.remove(tool_name)
                    self.orig_files.remove(tool_name)

                os.rename(fyle, fyle[:-5])
                self.orig_files.append(tool_name)
                count += 1
        if count == 0:
            raise CuckooPackageError("No tool found. Shouldn't ever occur.")

        return tool_name

    def start(self, path):
        self.temp_dir = os.getenv("Temp")
        self.tool_dir = os.path.join(self.temp_dir, "tool")

        start_dir = os.getcwd()
        if os.path.exists(self.tool_dir):
            os.chdir(self.tool_dir)
        else:
            raise CuckooPackageError("Tool directory not found on guest")

        # Get original files provided
        for fyle in os.listdir(self.tool_dir):
            self.orig_files.append(fyle)

        self.tool_name = self.get_tool_name()
        tool_path = os.path.join(self.tool_dir, self.tool_name + " ")

        options = self.options.get("tool_options", "")
        sample_options = self.options.get("sample_options", "")
        options = self.format_user_options(options, sample_options, path)

        log.info("Running command: " + tool_path + options)

        cmd_list = []
        cmd_list.append(tool_path)
        cmd_list.extend(options.split())

        # 0x08000000 = CREATE_NO_WINDOW
        # Either set creation flag to CREATE_NO_WINDOW
        # or disable the human auxiliary module
        # because the module will interfere with the running tool
        creation_flag = 0x08000000
        with open(self.log_file_name, 'w') as output_file:
            self.tool_process = Popen(cmd_list,
                                      stdout=output_file,
                                      stderr=output_file,
                                      creationflags=creation_flag,
                                      shell=False)
            self.tool_process.communicate()
        if self.tool_process < 0:
            raise CuckooPackageError("Unable to execute initial process, analysis aborted")

        # return to initial directory
        os.chdir(start_dir)
        return 0

    def check(self):
        """ Check to see if process has terminated.

        Returning `False` signals to analyzer.py that the analysis has been
        completed.
        """
        # If the process does not exist, os.kill will raise an OSError. We
        # assume this means it has already finished successfully. This does NOT
        # actually kill the process if it is running.
        try:
            os.kill(self.tool_process.pid, 0)
        except OSError:
            return False

        # `None` indicates that the process hasn't terminated yet.
        return (self.tool_process.poll() is None)

    def finish(self):
        upload_path = self.options.get("upload_path", "/tmp/upload")

        # remove original files from tool folder
        for fyle in self.orig_files:
            os.remove(os.path.join(self.tool_dir, fyle))
        # upload all files in the tool directory | %temp%\tool\
        for fyle in os.listdir(self.tool_dir):
            file_path = os.path.join(self.tool_dir, fyle)
            try:
                upload_to_host(file_path, os.path.join(upload_path, fyle))
            except (IOError) as e:
                CuckooPackageError("Unable to upload dropped file at path \"%s\": %s", file_path, e)

        return True
