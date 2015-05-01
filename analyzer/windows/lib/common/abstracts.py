# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import pickle
from subprocess import Popen

from lib.api.process import Process
from lib.common.results import upload_to_host
from lib.common.exceptions import CuckooPackageError

class Package(object):
    """Base abstract analysis package."""
    PATHS = []

    def __init__(self, options={}):
        """@param options: options dict."""
        self.options = options
        self.pids = []

    def set_pids(self, pids):
        """Update list of monitored PIDs in the package context.
        @param pids: list of pids.
        """
        self.pids = pids

    def start(self):
        """Run analysis package.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

    def check(self):
        """Check."""
        return True

    def _enum_paths(self):
        """Enumerate available paths."""
        for path in self.PATHS:
            basedir = path[0]
            if basedir == "SystemRoot":
                yield os.path.join(os.getenv("SystemRoot"), *path[1:])
            elif basedir == "ProgramFiles":
                yield os.path.join(os.getenv("ProgramFiles"), *path[1:])
                if os.getenv("ProgramFiles(x86)"):
                    yield os.path.join(os.getenv("ProgramFiles(x86)"),
                                       *path[1:])
            elif basedir == "HomeDrive":
                # os.path.join() does not work well when giving just C:
                # instead of C:\\, so we manually add the backslash.
                homedrive = os.getenv("HomeDrive") + "\\"
                yield os.path.join(homedrive, *path[1:])
            else:
                yield os.path.join(*path)

    def get_path(self, application):
        """Search for an application in all available paths.
        @param applicaiton: application executable name
        @return: executable path
        """
        for path in self._enum_paths():
            if os.path.exists(path):
                return path

        raise CuckooPackageError("Unable to find any %s executable." %
                                 application)

    def get_tool_path(self):
        tool_name = ""
        tool_dir = os.path.join(os.getenv("Temp"), "tool")
        for item in os.listdir(tool_dir):
            if item[-5:].lower() == ".tool":
                tool_name = item[:-5].lower()
                if tool_name in os.listdir(tool_dir):
                    os.remove(os.path.join(tool_dir, tool_name))
                os.rename(os.path.join(tool_dir, item), os.path.join(tool_dir, tool_name))
                break

        tool_path = os.path.join(tool_dir, tool_name)
        return tool_path

    def format_user_options(self, options, sample_options, path):

        if not options:
            options = ""
        if not sample_options:
            sample_options = ""
        if "$sample" in options:
            options = options.replace("$sample", path + " " + sample_options)
        else:
            options = options + " " + path + " " + sample_options


        return options.split()

    def execute(self, path, args):
        """Starts an executable for analysis.
        @param path: executable path
        @param args: executable arguments
        @return: process pid
        """
        dll = self.options.get("dll")
        free = self.options.get("free")
        tool = self.options.get("tool")

        suspended = True
        if free:
            suspended = False

        if tool:
            cwd = os.getcwd()
            os.chdir(os.path.join(os.getenv("Temp"), 'tool'))
            tool_path = self.get_tool_path()
            tool_args = self.options.get('tool-options')
            arg_list = self.format_user_options(tool_args, args, path)
            cmd_list = [tool_path]
            cmd_list.extend(arg_list)
            cmd_list = [val for val in cmd_list if val]
            # 0x08000000 = CREATE_NO_WINDOW
            # Either set creation flag to CREATE_NO_WINDOW
            # or disable the human auxiliary module
            # because the module will interfere with the running tool
            creation_flag = 0x08000000
            with open('tool_output.log', 'w+') as output_file:
                output_file.write(str(cmd_list) + "\n")
                self.tool_process = Popen(cmd_list,
                                          stdout=output_file,
                                          stderr=output_file,
                                          creationflags=creation_flag,
                                          shell=False)
                self.tool_process.communicate()

            os.chdir(cwd)
            if self.tool_process < 0:
                raise CuckooPackageError("Unable to execute initial process, analysis aborted")
            return self.tool_process.pid
        else:
            p = Process()
            if not p.execute(path=path, args=args, suspended=suspended):
                raise CuckooPackageError("Unable to execute the initial process, "
                                         "analysis aborted.")

            if not free and suspended:
                p.inject(dll)
                p.resume()
                p.close()
                return p.pid

    def package_files(self):
        """A list of files to upload to host.
        The list should be a list of tuples (<path on guest>, <name of file in package_files folder>).
        (package_files is a folder that will be created in analysis folder).
        """
        return None

    def finish(self):
        """Finish run.
        If specified to do so, this method dumps the memory of
        all running processes.
        """
        if self.options.get("procmemdump"):
            for pid in self.pids:
                p = Process(pid=pid)
                p.dump_memory()

        if self.options.get("tool"):
            upload_path = self.options.get("upload_path", "/tmp/upload")
            uploaded_tools = pickle.loads(self.options.get("uploaded_tools"))
            temp_dir = os.getenv("Temp")
            tool_dir = os.path.join(temp_dir, "tool")
            for root, subdirs, files in os.walk(tool_dir):
                for item in files:
                    if item not in uploaded_tools:
                        try:
                            upload_to_host(os.path.join(root, item), os.path.join("tool_output", item))
                        except (IOError) as e:
                            CuckooPackageError("Unable to upload dropped file at path \"%s\": %s", file_path, e)

        return True


class Auxiliary(object):
    def __init__(self, options={}):
        self.options = options
