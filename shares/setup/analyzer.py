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
import re
import sys
import logging
import hashlib
import ConfigParser
from shutil import *
from ctypes import *
from threading import Thread, Lock

sys.path.append("\\\\VBOXSVR\\setup\\lib\\")

import cuckoo.defines
from cuckoo.checkprocess import *
from cuckoo.execute import *
from cuckoo.inject import *
from cuckoo.paths import *
from cuckoo.screenshots import *
from cuckoo.tracer import *

log = logging.getLogger("Core")

#------------------------------ Global Variables ------------------------------#
# Initialize buffer size for Pipe server connections.
BUFSIZE = 512
# Initialize list of processes monitored by Cuckoo during current analysis.
PROCESS_LIST = []
# Initialize lock for process list operations.
PROCESS_LOCK = Lock()

# Initialize list of files opened by the monitored processes. Once analysis
# is completed, these files get dumped.
FILES_LIST = []
# Initialize lock for files list operations.
FILES_LOCK = Lock()
#------------------------------------------------------------------------------#

class AnalyzerConfig:
    """
    Parses analyzer config file.
    """

    def __init__(self):
        config_path = os.path.join(CUCKOO_SETUP_SHARE, "conf\\analyzer.conf")
        config = ConfigParser.ConfigParser()
        config.read(config_path)

        # Get screenshots capture option.
        self.screenshots = config.get("Analysis", "screenshots").strip().lower()

        # Get filtered files list.
        filtered = config.get("DroppedFiles", "filter").strip().split(",")
        self.filtered = [md5.lower() for md5 in filtered]

class AnalysisConfig:
    """
    Parses analysis config file.
    """

    def __init__(self, config_path):
        config = ConfigParser.ConfigParser()
        config.read(config_path)

        self.target = config.get("analysis", "target")
        self.package = config.get("analysis", "package")
        self.timeout = config.get("analysis", "timeout")
        self.share = config.get("analysis", "share")

def install_dependencies():
    """
    Installs system dependencies to Windows system32.
    """
    log = logging.getLogger("Core.InstallDependencies")

    # Check if Cuckoo's directory for system dependencies exist, otherwise
    # abort.
    if not os.path.exists(SYSTEM_SETUP_SRC):
        log.critical("Source system setup does not exist at path \"%s\"."
                     % SYSTEM_SETUP_SRC)
        return False

    system32 = os.path.join(os.getenv("SystemRoot"), "system32")

    # Not likely to happen :P, but if Windows' System32 folder does not exist
    # I obviously need to abort.
    if not os.path.exists(system32):
        log.critical("Windows system root \"%s\" does not exist!" % system32)
        return False

    try:
        if os.path.isdir(SYSTEM_SETUP_SRC):
            names = os.listdir(SYSTEM_SETUP_SRC)

            # Walk through all the files in source folder and copy them.
            for name in names:
                current_path = os.path.join(SYSTEM_SETUP_SRC, name)

                log.info("Installing dependency \"%s\"." % current_path)

                # If current path is a directory copy recursively everything
                # contained in it.
                if os.path.isdir(current_path):
                    copytree(current_path, os.path.join(system32, name))
                # If it's a file, just copy it to Windows' system32.
                else:
                    copy(current_path, system32)
        else:
            log.critical("System setup path \"%s\" is not a valid directory."
                         % SYSTEM_SETUP_SRC)
            return False
    except (IOError, os.error), why:
        log.critical("Something went wrong while installing dependencies: %s."
                     % why)
        return False

    return True

def install_cuckoo():
    """
    Installs Cuckoo files.
    """
    log = logging.getLogger("Core.InstallCuckoo")

    if not os.path.exists(CUCKOO_SETUP_SRC):
        log.critical("Cuckoo setup does not exist at path \"%s\"."
                     % CUCKOO_SETUP_SRC)
        return False

    # Generally Cuckoo's install destination path is C:\cuckoo. This folder
    # shouldn't already exist, so I create it. If I can't, analysis is aborted.
    if not os.path.exists(CUCKOO_PATH):
        try:
            os.mkdir(CUCKOO_PATH)
        except (IOError, os.error), why:
            log.critical("Something went wrong while creating directory " \
                         "\"%s\": %s." % (CUCKOO_PATH, why))
            return False

    try:
        if os.path.isdir(CUCKOO_SETUP_SRC):
            names = os.listdir(CUCKOO_SETUP_SRC)

            for name in names:
                current_path = os.path.join(CUCKOO_SETUP_SRC, name)

                log.info("Installing \"%s\"." % current_path)

                if os.path.isdir(current_path):
                    copytree(current_path, os.path.join(CUCKOO_PATH, name))
                else:
                    copy(current_path, CUCKOO_PATH)
        else:
            log.critical("Cuckoo setup path \"%s\" is not a valid directory."
                         % CUCKOO_SETUP_SRC)
            return False
    except (IOError, os.error), why:
        log.critical("Something went wrong while installing Cuckoo: %s." % why)
        return False

    return True

def install_target(share_path, target_name):
    """
    Copies target file to be analyzed to system drive.
    @return: path to the newly copied file
    """
    log = logging.getLogger("Core.InstallTarget")

    target_src = os.path.join(share_path, target_name)
    target_dst = "%s\\" % os.getenv("SystemDrive")

    if not os.path.exists(target_src):
        log.critical("Cannot find target file at path \"%s\"." % target_src)
        return False

    log.info("Installing target file from \"%s\" to \"%s\"."
             % (target_src, target_dst))

    try:
        copy(target_src, target_dst)
    except (IOError, os.error, Error), why:
        log.critical("Something went wrong while copying file from \"%s\" to " \
                     "\"%s\": %s." % (target_src, target_dst, why))
        return False

    return "%s\\%s" % (os.getenv("SystemDrive"), target_name)

def add_file_to_list(file_path):
    """
    Adds the specified path to the dump list.
    @param file_path: path to the file to be dumped
    """
    global FILES_LIST
    global FILES_LOCK
    log = logging.getLogger("Core.AddFile")
    
    FILES_LOCK.acquire()
    
    if not file_path in FILES_LIST:
        log.info("Newly created file path added to list: %s" % file_path)
        FILES_LIST.append(file_path)
        
    FILES_LOCK.release()
    
    return True

def is_file_filtered(file_path):
    """
    Checks if specified file is filtered and should not be dumped.
    @param file_path: path to file to check
    """
    log = logging.getLogger("Core.IsFileFiltered")

    if not os.path.exists(file_path):
        return False

    try:
        md5 = hashlib.md5(open(file_path, "rb").read()).hexdigest()
    except:
        md5 = ""

    filtered = AnalyzerConfig().filtered

    # Check if the calculated MD5 hash appears in the filter.
    if len(filtered) > 0:
        if md5 in filtered:
            log.debug("Dropped file \"%s\" has a filtered MD5 hash \"%s\". Skip."
                      % (file_path, md5))
            return True

    return False
    
def dump_files():
    """
    Dumps all intercepted files.
    """
    global FILES_LIST
    log = logging.getLogger("Core.DumpFiles")
    
    for file_path in FILES_LIST:
        dir_dst = os.path.join(CUCKOO_PATH, "files")
    
        if not os.path.exists(file_path):
            log.debug("Dropped file \"%s\" does not exist. Skip." % file_path)
            continue

        # If file is in filtered list, I'm gonna skip it.
        if is_file_filtered(file_path):
            continue

        try:
            if os.path.getsize(file_path) == 0:
                log.debug("Dropped file \"%s\" is empty. Skip." % file_path)
                continue

            copy(file_path, dir_dst)
            log.info("Dropped file \"%s\" successfully dumped to \"%s\"."
                     % (file_path, dir_dst))
        except Exception, why:
            log.error("Something went wrong while dumping file from \"%s\" " \
                      "to \"%s\": %s." % (file_path, dir_dst, why))
            continue
            
    return True

def save_results(share_path):
    """
    Copies analysis results from local directory to the specified shared folder.
    @param share_path: path to the shared folder
    """
    log = logging.getLogger("Core.SaveResults")

    analysis_dirs = []
    analysis_dirs.append("logs")
    analysis_dirs.append("files")
    analysis_dirs.append("shots")
    analysis_dirs.append("trace")

    log.info("Saving analysis results to \"%s\"." % share_path)

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
            log.error("Something went wrong while saving results from " \
                      "\"%s\" to \"%s\": %s." % (dir_src, dir_dst, why))
            return False

    return True

# This class handles new Pipe connections.
class PipeHandler(Thread):
    """
    Handles connections to the pipe server.
    """

    def __init__(self, h_pipe):
        Thread.__init__(self)
        self.h_pipe = h_pipe

    def run(self):
        global PROCESS_LOCK
        PROCESS_LOCK.acquire()
        log = logging.getLogger("Core.PipeHandler")

        try:
            data = create_string_buffer(BUFSIZE)
    
            # Read data from pipe connection.
            while True:
                bytes_read = c_int(0)
    
                success = cuckoo.defines.KERNEL32.ReadFile(self.h_pipe,
                                                           data,
                                                           sizeof(data),
                                                           byref(bytes_read),
                                                           None)
    
                if not success or bytes_read.value == 0:
                    if cuckoo.defines.KERNEL32.GetLastError() == cuckoo.defines.ERROR_BROKEN_PIPE:
                        # Client disconnected.
                        pass
    
                    break

            if data:
                command = data.value.strip()
                
                # If the acquired data is a valid PID to monitor, inject it.
                if re.match("PID:", command):
                    pid = int(command[4:])
                    log.debug("Received request to analyze process with PID %d."
                              % pid)

                    if pid > -1:
                        # Check if the process has not been injected previously.
                        if pid not in PROCESS_LIST:
                            # If injection is successful, add the newly monitored
                            # process to global list too.
                            if cuckoo_inject(pid, CUCKOO_DLL_PATH):
                                PROCESS_LIST.append(pid)
                            else:
                                log.error("Failed injecting process with "
                                          "PID \"%s\" (0x%08x)." % (pid, pid))
                        else:
                            log.debug("Process with PID \"%d\" (0x%08x) " \
                                      "already in monitored process list. Skip."
                                      % (pid, pid))
                # If the acquired data is a path to a file to dump, add it to
                # the list.
                elif re.match("FILE:", command):
                    file_path = command[5:]
                    add_file_to_list(file_path)
        finally:
            PROCESS_LOCK.release()

        return True

class PipeServer(Thread):
    """
    Spawns a pipe server used to receive communications from the injected
    malware processes.
    """

    def __init__(self, pipe_name = CUCKOO_PIPE):
        Thread.__init__(self)
        self.pipe_name = pipe_name
        self._do_run = True

    def stop(self):
        """
        Stops pipe server.
        """
        log = logging.getLogger("Core.PipeServer")
        log.info("Stopping Pipe Server.")
        self._do_run = False

    def run(self):
        """
        Runs pipe server thread.
        """
        log = logging.getLogger("Core.PipeServer")
        log.info("Starting Pipe Server.")

        while self._do_run:
            h_pipe = cuckoo.defines.KERNEL32.CreateNamedPipeA(self.pipe_name,
                                                              cuckoo.defines.PIPE_ACCESS_DUPLEX,
                                                              cuckoo.defines.PIPE_TYPE_MESSAGE | \
                                                              cuckoo.defines.PIPE_READMODE_MESSAGE | \
                                                              cuckoo.defines.PIPE_WAIT,
                                                              cuckoo.defines.PIPE_UNLIMITED_INSTANCES,
                                                              BUFSIZE,
                                                              BUFSIZE,
                                                              0,
                                                              None)

            # If pipe handle is invalid, something went wrong with its creation,
            # and I terminate the server.
            if h_pipe == cuckoo.defines.INVALID_HANDLE_VALUE:
                log.error("Pipe Server failed to start (GLE=%d)."
                          % cuckoo.defines.KERNEL32.GetLastError())
                return False

            # Wait for pipe connections. More informations at:
            # http://msdn.microsoft.com/en-us/library/aa365146%28v=vs.85%29.aspx
            if cuckoo.defines.KERNEL32.ConnectNamedPipe(h_pipe, None):
                p = PipeHandler(h_pipe)
                a = p.start()
            else:
                # If there's no connection, close the Pipe handle and loop it
                # over again.
                cuckoo.defines.KERNEL32.CloseHandle(h_pipe)

        return True

def main(config_path):
    """
    Main analyzer procedure.
    @param config_path: path to the analysis config file
    """
    global PROCESS_LIST
    global PROCESS_LOCK
    pid_list = None
    shots = None
    check_for_processes = True

    log = logging.getLogger("Core.Analyzer")
    log.info("Cuckoo starting with PID %d." % os.getpid())

    if not os.path.exists(config_path):
        return False
    
    config = AnalysisConfig(config_path)
    analyzer = AnalyzerConfig()

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
        log.info("Analysis package imported from \"%s\"." % package_name)
    except ImportError, why:
        log.error("Unable to import analysis package: %s." % why)
        return False

    #---------------------------------------------------------------------------
    # Temporary hacky fix to wait for Windows VM to complete network link setup.
    import time
    time.sleep(10)
    #---------------------------------------------------------------------------

    # If enabled in configuration, start capturing screenshots of Windows'
    # desktop during malware's execution.
    if analyzer.screenshots == "on":
        shots = Screenshots()
        shots.daemon = True
        shots.start()

    # Launch main function from analysis package.
    try:
        log.info("Executing analysis package run function.")
        pid_list = package.cuckoo_run(target_path)
    except Exception, why:
        log.error("Unable to launch analysis package \"%s\" main function: %s"
                  % (config.package, why))
        return False

    # Add returned process IDs to the list of monitored ones.
    if pid_list:
        for pid in pid_list:
            if pid > -1:
                PROCESS_LIST.append(pid)
                log.info("Analysis package returned following process PID to " \
                         "add to monitor list: %d." % pid)
    # If no process IDs are returned, I must assume that the current analysis
    # package doesn't perform any injection. Consequently I should not wait
    # for active processes to exit, or the analysis would end prematurely.
    else:
        log.info("No process PIDs returned to monitor.")
        check_for_processes = False

    # If no analysis timeout is set in the configuration file, it'll use
    # standard 3 minutes.
    if not config.timeout or config.timeout == 0:
        timeout = 180
    else:
        timeout = int(config.timeout)

    log.info("Running for a maximum of %d seconds." % timeout)

    # Initialize timeout counter.
    counter = 0
    # The following checks are performed until the specified timeout is hit.
    while counter in xrange(0, timeout):
        PROCESS_LOCK.acquire()
        
        try:
            if check_for_processes:
                # Walk through monitored processes in the list.
                for process_id in PROCESS_LIST:
                    # If process is inactive increase inactive counter.
                    if not check_process(process_id):
                        log.info("Process with PID %d terminated." % process_id)
                        PROCESS_LIST.remove(process_id)
        
                # If inactive counter is equal to the total number of monitored
                # processes, means that I'm done with the analysis.
                if len(PROCESS_LIST) == 0:
                    break

            # Launching custom check function from selected analysis package.
            # This function allows the user to specify custom events that would
            # require the analysis to terminate.
            # Thanks to KjellChr for suggesting this feature.
            try:
                if not package.cuckoo_check():
                    log.info("The check function from package \"%s\" " \
                             "requested to terminate analysis."
                             % config.package)
                    break
            except Exception, why:
                log.error("Something went wrong while launching analysis " \
                          "package \"%s\"'s check function: %s" \
                          % (config.package, why))
        finally:
            counter += 1
            PROCESS_LOCK.release()
            cuckoo.defines.KERNEL32.Sleep(1000)

    # Stop Pipe Server.
    pipe.stop()
    # Stop taking screenshots.
    if shots:
        shots.stop()

    log.info("Analysis completed.")

    # Launching custom finish function from selected analysis package.
    # This function allows the user to specify any custom operation to be done
    # on the analysis machine before shutting it down.
    try:
        log.info("Executing analysis package \"%s\" custom finish function."
                 % config.package)
        package.cuckoo_finish()
    except Exception, why:
        log.error("Something went wrong while launching analysis package " \
                  "\"%s\"'s finish function: %s." % (config.package, why))

    # Try to dump the dropped files.
    dump_files()

    if not save_results(config.share):
        return False

    return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(-1)

    # Path to the shared folder where to save results.
    local_share = sys.argv[1]

    # Check if the shared folder is actually accessible, otherwise abort
    # execution.
    if not os.path.exists(local_share):
        sys.exit(-1)

    # Setup logging configuration.
    log = logging.getLogger()
    formatter = logging.Formatter('[%(asctime)s] [%(name)s] %(levelname)s: %(message)s')
    stream_handler = logging.StreamHandler()
    file_handler = logging.FileHandler(os.path.join(local_share, "analysis.log"))
    file_handler.setFormatter(formatter)
    stream_handler.setFormatter(formatter)
    log.addHandler(file_handler)
    log.addHandler(stream_handler)
    log.setLevel(logging.DEBUG)

    # Get path for the current analysis configuration file.
    config_path = os.path.join(local_share, "analysis.conf")

    # If the analysis.conf file related to this analysis does not exist, I have
    # to abort.
    if not os.path.exists(config_path):
        log.critical("Cannot find analysis config file at \"%s\". Abort."
                     % config_path)
        sys.exit(-1)

    # Launch analysis and retrieve a boolean value representing
    # analysis' success or failure.
    success = main(config_path)

    # Return proper exit code depending on analysis success or
    # failure.
    if success:
        sys.exit(0)
    else:
        sys.exit(-1)
