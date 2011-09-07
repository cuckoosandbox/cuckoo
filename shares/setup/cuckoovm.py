#!/usr/bin/python
# Cuckoo Sandbox - Automated Malware Analysis
# Copyright (C) 2010-2011  Claudio "nex" Guarnieri (nex@cuckoobox.org)
# http://www.cuckoobox.org
#
# This file is part of Cuckoo.
#
# Cuckoo is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Cuckoo is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/.

import os
import sys
import ConfigParser
from ctypes import *
from threading import Thread, Lock
from shutil import *

sys.path.append("\\\\VBOXSVR\\setup\\lib\\")

from cuckoo.checkprocess import *
from cuckoo.defines import *
from cuckoo.execute import *
from cuckoo.inject import *
from cuckoo.logging import *
from cuckoo.paths import *
from cuckoo.screenshots import *

# Initialize buffer size for Pipe server connections.
BUFSIZE = 512
# Initialize list of processes monitored by Cuckoo during current analysis.
PROCESS_LIST = []
# Initialize lock for process list operations.
PROCESS_LOCK = Lock()

def install_dependencies():
    if not os.path.exists(SYSTEM_SETUP_SRC):
        log("System setup does not exist at path \"%s\"." % SYSTEM_SETUP_SRC,
            "ERROR")
        return False

    system32 = os.path.join(os.getenv("SystemRoot"), "system32")

    if not os.path.exists(system32):
        log("%s does not exist!", "ERROR")
        return False

    try:
        if os.path.isdir(SYSTEM_SETUP_SRC):
            names = os.listdir(SYSTEM_SETUP_SRC)

            for name in names:
                current_path = os.path.join(SYSTEM_SETUP_SRC, name)

                log("Installing dependency \"%s\"." % current_path)

                # If current path is a directory copy recursively also
                # everything contained in it.
                if os.path.isdir(current_path):
                    copytree(current_path, os.path.join(system32, name))
                # If it's a file, just copy it to Cuckoo's root.
                else:
                    copy(current_path, system32)
        else:
            log("System setup path \"%s\" is not a valid directory."
                % SYSTEM_SETUP_SRC, "ERROR")
            return False
    except (IOError, os.error), why:
        log("Something went wrong while installing dependencies: %s." % why,
            "ERROR")
        return False

    return True

# Copy Cuckoo core analysis components to destination setup directory.
def install_cuckoo():
    if not os.path.exists(CUCKOO_SETUP_SRC):
        log("Cuckoo setup does not exist at path \"%s\"." % CUCKOO_SETUP_SRC,
            "ERROR")
        return False

    log("Installing Cuckoo")

    # Generally Cuckoo's install destination path is C:\cuckoo. This folder
    # shouldn't already exist, so I create it. If I can't, analysis is aborted.
    if not os.path.exists(CUCKOO_PATH):
        try:
            os.mkdir(CUCKOO_PATH)
        except (IOError, os.error), why:
            log("Cannot create directory \"%s\": %s." % (CUCKOO_PATH, why),
                "ERROR")
            return False

    # Start processing through all files and directories contained in Cuckoo's
    # source setup folder.
    try:
        # This check should totally make no sense, but whatever.
        if os.path.isdir(CUCKOO_SETUP_SRC):
            names = os.listdir(CUCKOO_SETUP_SRC)

            for name in names:
                current_path = os.path.join(CUCKOO_SETUP_SRC, name)

                log("Installing \"%s\"." % current_path)

                # If current path is a directory copy recursively also
                # everything contained in it.
                if os.path.isdir(current_path):
                    copytree(current_path, os.path.join(CUCKOO_PATH, name))
                # If it's a file, just copy it to Cuckoo's root.
                else:
                    copy(current_path, CUCKOO_PATH)
        else:
            log("Cuckoo setup path \"%s\" is not a valid directory."
                % CUCKOO_SETUP_SRC, "ERROR")
            return False
    except (IOError, os.error), why:
        log("Something went wrong while installing Cuckoo: %s." % why, "ERROR")
        return False

    return True

def install_target(share_path, target_name):
    target_src = os.path.join(share_path, target_name)
    target_dst = "%s\\" % os.getenv("SystemDrive")

    if not os.path.exists(target_src):
        log("Cannot find target file at path \"%s\"." % target_src, "ERROR")
        return False

    log("Installing target file from \"%s\" to \"%s\"."
        % (target_src, target_dst))

    # Copy analysis' target file to system drive folder.
    try:
        copy(target_src, target_dst)
    except (IOError, os.error, Error), why:
        log("Cannot copy target file from \"%s\" to \"%s\": %s."
            (target_src, target_dst, why), "ERROR")
        return False

    # Return path to the newly copied file.
    return "%s\\%s" % (os.getenv("SystemDrive"), target_name)

# Copy analysis results from Guest installation folder to shared folder.
def save_results(share_path):
    analysis_dirs = []
    analysis_dirs.append("logs")
    analysis_dirs.append("files")
    analysis_dirs.append("shots")

    log("Saving analysis results to \"%s\"." % share_path)

    # Walk through all results directories and try to copy them to the shared
    # folder.
    for dir_name in analysis_dirs:
        dir_src = os.path.join(CUCKOO_PATH, dir_name)
        dir_dst = os.path.join(share_path, dir_name)

        if not os.path.exists(dir_src):
            continue

        if os.path.exists(dir_dst):
            continue

        try:
            copytree(dir_src, dir_dst)
        except (IOError, os.error), why:
            log("Cannot save results from \"%s\" to \"%s\": %s."
                % (dir_src, dir_dst, why), "ERROR")
            return False

    return True

# This class handles new Pipe connections.
class PipeHandler(Thread):
    def __init__(self, h_pipe):
        Thread.__init__(self)
        self.h_pipe = h_pipe

    def run(self):
        global PROCESS_LOCK
        PROCESS_LOCK.acquire()

        try:
            data = create_string_buffer(BUFSIZE)
    
            # Read data from pipe connection.
            while True:
                bytes_read = c_int(0)
    
                success = KERNEL32.ReadFile(self.h_pipe,
                                            data,
                                            sizeof(data),
                                            byref(bytes_read),
                                            None)
    
                if not success or bytes_read.value == 0:
                    if KERNEL32.GetLastError() == ERROR_BROKEN_PIPE:
                        # Client disconnected. This check is quite irrelevant.
                        pass
    
                    break
    
            # If we acquired any data that must be a valid process ID we need to
            # inject our DLL in.
            if data:
                pid = int(data.value.strip())
    
                if pid > -1:
                    # Check if the process has not been injected previously.
                    if pid not in PROCESS_LIST:
                        # If injection is successful, add the newly monitored
                        # process to global list too.
                        if cuckoo_inject(pid, CUCKOO_DLL_PATH):
                            log("Process with ID \"%d\" (0x%08x) successfully " \
                                "injected." % (pid, pid))
                            PROCESS_LIST.append(pid)
                        else:
                            log("Failed injecting process with ID \"%s\" (0x%08x)."
                                % (pid, pid), "ERROR")
                    else:
                        log("Process with ID \"%d\" (0x%08x) already in monitored" \
                            " process list. Skip." % (pid, pid))
        finally:
            PROCESS_LOCK.release()

        return True

# This is the threaded Pipe server which listen for notifications from the
# injected DLLs.
class PipeServer(Thread):
    def __init__(self, pipe_name = CUCKOO_PIPE):
        Thread.__init__(self)
        self.pipe_name = pipe_name

    def run(self):
        log("Starting Pipe Server")

        while True:
            # Create named pipe with a name defined in paths.py.
            h_pipe = KERNEL32.CreateNamedPipeA(self.pipe_name,
                                               PIPE_ACCESS_DUPLEX,
                                               PIPE_TYPE_MESSAGE |     \
                                               PIPE_READMODE_MESSAGE | \
                                               PIPE_WAIT,
                                               PIPE_UNLIMITED_INSTANCES,
                                               BUFSIZE,
                                               BUFSIZE,
                                               0,
                                               None)

            # If pipe handle is invalid, something went wrong with its creation,
            # and I terminate the server.
            if h_pipe == INVALID_HANDLE_VALUE:
                log("Pipe Server failed to start.", "ERROR")
                return False

            # Wait for pipe connections. More informations at:
            # http://msdn.microsoft.com/en-us/library/aa365146%28v=vs.85%29.aspx
            if KERNEL32.ConnectNamedPipe(h_pipe, None):
                # If there's a new connection, call the handler.
                log("New connection to the Pipe server, handling it.")
                p = PipeHandler(h_pipe)
                a = p.start()
            else:
                # If there's no connection, close the Pipe handle and loop it
                # over again.
                KERNEL32.CloseHandle(h_pipe)

        return True

class Config:
    def __init__(self, config_path):
        config = ConfigParser.ConfigParser()
        config.read(config_path)

        self.target = config.get("analysis", "target")
        self.package = config.get("analysis", "package")
        self.timeout = config.get("analysis", "timeout")
        self.share = config.get("analysis", "share")

# This is the main procedure.
def main(config_path):
    global PROCESS_LIST
    global PROCESS_LOCK
    pid_list = None

    log("Cuckoo starting with PID %s." % os.getpid())

    # Check again if the config file exists. This should be a completely
    # useless check, but better be 300% sure.
    if not os.path.exists(config_path):
        return False
    
    # Parse config file.
    config = Config(config_path)

    # Install system dependencies.
    if not install_dependencies():
        return False

    # Install Cuckoo core analysis components to system drive. Obviously if
    # it fails we need to abort execution.
    if not install_cuckoo():
        return False

    # Copy target file to system drive.
    target_path = install_target(config.share, config.target)
    if not target_path:
        return False

    # Create the Pipe Server, daemonize it and start it. It shouldn't fail, but
    # if it does I don't actually care too much, as I can still get analysis
    # results of the original process.
    pipe = PipeServer()
    pipe.daemon = True
    pipe.start()

    # Start taking screenshots of current execution.
    shots = Screenshots()
    shots.daemon = True
    shots.start()

    # This is important.
    # Try to dinamically import the analysis package specified in the config
    # file.
    try:
        package_name = "packages.%s" % config.package
        package = __import__(package_name,
                             globals(),
                             locals(),
                             ['cuckoo_run'],
                             -1)
        log("Analysis package imported from \"%s\"." % package_name)
    except ImportError, why:
        log("Unable to import analysis package: %s." % why, "ERROR")
        return False

    # Launch main function from analysis package. Default packages won't create
    # any problem, but if its using one created by the user, something might
    # fail if it wasn't properly written.
    try:
        log("Executing analysis package run function.")
        pid_list = package.cuckoo_run(target_path)
    except Exception, why:
        log("Unable to launch analysis package \"%s\" main function: %s."
            % (config.package, why), "ERROR")
        return False

    # If injection was successful, add the pid to the list of monitored
    # processes.
    if pid_list and len(pid_list) > 0:
        for pid in pid_list:
            if pid > -1:
                PROCESS_LIST.append(pid)
                log("Analysis package returned following process ID to add to" \
                    " monitor list: %d." % pid)
    else:
        return False

    # If no analysis timeout is set in the configuration file, it'll use
    # standard 3 minutes.
    if not config.timeout or config.timeout == 0:
        timeout = 180
    else:
        timeout = int(config.timeout)

    log("Running for a maximum of %d seconds." % timeout)

    # Initialize timeout counter.
    counter = 0
    # The following checks are performed until the specified timeout is hit.
    while counter in xrange(0, timeout):
        PROCESS_LOCK.acquire()
        
        try:
            # Walk through monitored processes in the list.
            for process_id in PROCESS_LIST:
                # If process is inactive increase inactive counter.
                if not check_process(process_id):
                    log("Process with ID %d terminated." % process_id)
                    PROCESS_LIST.remove(process_id)
    
            # If inactive counter is equal to the total number of monitored
            # processes, means that I'm done with the analysis.
            if len(PROCESS_LIST) == 0:
                break
        finally:
            counter += 1
            PROCESS_LOCK.release()
            KERNEL32.Sleep(1000)

    log("Analysis completed.")

    # Stop taking screenshots.
    shots.stop()

    if not save_results(config.share):
        return False

    return True

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # The argument for script's invocation must be the shared folder where
        # Cuckoo will be able to get the analysis config file and write the
        # results back.
        local_share = sys.argv[1]

        # Check if the shared folder is actually accessible, otherwise abort
        # execution.
        if os.path.exists(local_share):
            # In case something fails with the analysis log file, I'll use a
            # "backup" one.
            backup_log_path = os.path.join(local_share, "analysis.log")
            # Get path for the current analysis configuration file.
            config_path = os.path.join(local_share, "analysis.conf")

            if os.path.exists(config_path):
                log("Starting analysis procedure.")
                # Launch analysis and retrieve a boolean value representing
                # analysis' success or failure.
                success = main(config_path)

                # Once analysis is finished and analysis results are already
                # saved, I also want to copy analysis log file.
                if os.path.exists(LOG_PATH_DEFAULT):
                    try:
                        copy(LOG_PATH_DEFAULT, local_share)
                    except (IOError, os.error, Error), why:
                        log("Unable to copy analysis log file from \"%s\" " \
                            "to \"%s\": %s."
                            % (LOG_PATH_DEFAULT, local_share, why),
                            "ERROR",
                            backup_log_path)
                else:
                    log("Unable to find analysis log file at \"%s\".",
                        "ERROR",
                        backup_log_path)

                # Return proper exit code depending on analysis success or
                # failure.
                if success:
                    sys.exit(0)
                else:
                    sys.exit(-1)
            else:
                log("Unable to find analysis config file at \"%s\"."
                    % config_path, "ERROR", backup_log_path)
                sys.exit(-1)
        else:
            sys.exit(-1)
