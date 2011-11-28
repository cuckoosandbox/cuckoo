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

def install_dependencies():
    log = logging.getLogger("Core.InstallDependencies")

    if not os.path.exists(SYSTEM_SETUP_SRC):
        log.error("System setup does not exist at path \"%s\"."
                  % SYSTEM_SETUP_SRC)
        return False

    system32 = os.path.join(os.getenv("SystemRoot"), "system32")

    if not os.path.exists(system32):
        log.error("Windows system root \"%s\" does not exist!" % system32)
        return False

    try:
        if os.path.isdir(SYSTEM_SETUP_SRC):
            names = os.listdir(SYSTEM_SETUP_SRC)

            for name in names:
                current_path = os.path.join(SYSTEM_SETUP_SRC, name)

                log.info("Installing dependency \"%s\"." % current_path)

                # If current path is a directory copy recursively also
                # everything contained in it.
                if os.path.isdir(current_path):
                    copytree(current_path, os.path.join(system32, name))
                # If it's a file, just copy it to Cuckoo's root.
                else:
                    copy(current_path, system32)
        else:
            log.error("System setup path \"%s\" is not a valid directory."
                      % SYSTEM_SETUP_SRC)
            return False
    except (IOError, os.error), why:
        log.error("Something went wrong while installing dependencies: %s."
                  % why)
        return False

    return True

# Copy Cuckoo core analysis components to destination setup directory.
def install_cuckoo():
    log = logging.getLogger("Core.InstallCuckoo")

    if not os.path.exists(CUCKOO_SETUP_SRC):
        log.error("Cuckoo setup does not exist at path \"%s\"."
                  % CUCKOO_SETUP_SRC)
        return False

    # Generally Cuckoo's install destination path is C:\cuckoo. This folder
    # shouldn't already exist, so I create it. If I can't, analysis is aborted.
    if not os.path.exists(CUCKOO_PATH):
        try:
            os.mkdir(CUCKOO_PATH)
        except (IOError, os.error), why:
            log.error("Something went wrong while creating directory " \
                      "\"%s\": %s." % (CUCKOO_PATH, why))
            return False

    # Start processing through all files and directories contained in Cuckoo's
    # source setup folder.
    try:
        # This check should totally make no sense, but whatever.
        if os.path.isdir(CUCKOO_SETUP_SRC):
            names = os.listdir(CUCKOO_SETUP_SRC)

            for name in names:
                current_path = os.path.join(CUCKOO_SETUP_SRC, name)

                log.info("Installing \"%s\"." % current_path)

                # If current path is a directory copy recursively also
                # everything contained in it.
                if os.path.isdir(current_path):
                    copytree(current_path, os.path.join(CUCKOO_PATH, name))
                # If it's a file, just copy it to Cuckoo's root.
                else:
                    copy(current_path, CUCKOO_PATH)
        else:
            log.error("Cuckoo setup path \"%s\" is not a valid directory."
                      % CUCKOO_SETUP_SRC)
            return False
    except (IOError, os.error), why:
        log.error("Something went wrong while installing Cuckoo: %s." % why)
        return False

    return True

def install_target(share_path, target_name):
    log = logging.getLogger("Core.InstallTarget")
    target_src = os.path.join(share_path, target_name)
    target_dst = "%s\\" % os.getenv("SystemDrive")

    if not os.path.exists(target_src):
        log.error("Cannot find target file at path \"%s\"." % target_src)
        return False

    log.info("Installing target file from \"%s\" to \"%s\"."
             % (target_src, target_dst))

    # Copy analysis' target file to system drive folder.
    try:
        copy(target_src, target_dst)
    except (IOError, os.error, Error), why:
        log.error("Something went wrong while copying file from \"%s\" to " \
                  "\"%s\": %s." % (target_src, target_dst, why))
        return False

    # Return path to the newly copied file.
    return "%s\\%s" % (os.getenv("SystemDrive"), target_name)

# Add the specified path to the list of files that need to be dumped.
def add_file_to_list(file_path):
    global FILES_LIST
    global FILES_LOCK
    log = logging.getLogger("Core.AddFile")
    
    FILES_LOCK.acquire()
    
    if not file_path in FILES_LIST:
        log.info("Newly created file path added to list: %s" % file_path)
        FILES_LIST.append(file_path)
        
    FILES_LOCK.release()
    
    return True
    
# Store dumped files.
def dump_files():
    global FILES_LIST
    log = logging.getLogger("Core.DumpFiles")
    
    for file_path in FILES_LIST:
        dir_dst = os.path.join(CUCKOO_PATH, "files")
    
        if not os.path.exists(file_path):
            log.debug("Dropped file \"%s\" does not exist." % file_path)
            continue
            
        try:
            if os.path.getsize(file_path) == 0:
                log.debug("Dropped file \"%s\" is empty." % file_path)
                continue

            copy(file_path, dir_dst)
            log.info("Dropped file \"%s\" successfully dumped to \"%s\"."
                     % (file_path, dir_dst))
        except Exception, why:
            log.error("Something went wrong while dumping file from \"%s\" " \
                      "to \"%s\": %s." % (file_path, dir_dst, why))
            continue
            
    return True

# Copy analysis results from Guest installation folder to shared folder.
def save_results(share_path):
    log = logging.getLogger("Core.SaveResults")

    analysis_dirs = []
    analysis_dirs.append("logs")
    analysis_dirs.append("files")
    analysis_dirs.append("shots")
    analysis_dirs.append("instructions")

    log.info("Saving analysis results to \"%s\"." % share_path)

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
            log.error("Something went wrong while saving results from " \
                      "\"%s\" to \"%s\": %s." % (dir_src, dir_dst, why))
            return False

    return True

# This class handles new Pipe connections.
class PipeHandler(Thread):
    def __init__(self, h_pipe):
        Thread.__init__(self)
        self.h_pipe = h_pipe

    def run(self):
        global PROCESS_LOCK
        log = logging.getLogger("Core.PipeHandler")
        PROCESS_LOCK.acquire()

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
                        # Client disconnected. This check is quite irrelevant.
                        pass
    
                    break
    
            # If we acquired any data that must be a valid process ID we need to
            # inject our DLL in.
            if data:
                command = data.value.strip()
                
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
                elif re.match("FILE:", command):
                    file_path = command[5:]
                    add_file_to_list(file_path)
        finally:
            PROCESS_LOCK.release()

        return True

# This is the threaded Pipe server which listen for notifications from the
# injected DLLs.
class PipeServer(Thread):
    def __init__(self, pipe_name = CUCKOO_PIPE):
        Thread.__init__(self)
        self.pipe_name = pipe_name
        self._do_run = True

    def stop(self):
        log = logging.getLogger("Core.PipeServer")
        log.info("Stopping Pipe Server.")
        self._do_run = False

    def run(self):
        log = logging.getLogger("Core.PipeServer")
        log.info("Starting Pipe Server.")

        while self._do_run:
            # Create named pipe with a name defined in paths.py.
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
                # If there's a new connection, call the handler.
                p = PipeHandler(h_pipe)
                a = p.start()
            else:
                # If there's no connection, close the Pipe handle and loop it
                # over again.
                cuckoo.defines.KERNEL32.CloseHandle(h_pipe)

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
    log = logging.getLogger("Core.Analyzer")
    pid_list = None
    check_for_processes = True

    log.info("Cuckoo starting with PID %d." % os.getpid())

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

    # Start taking screenshots of current execution.
    shots = Screenshots()
    shots.daemon = True
    shots.start()

    # Launch main function from analysis package. Default packages won't create
    # any problem, but if its using one created by the user, something might
    # fail if it wasn't properly written.
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
            # require the analysis to terminate. For example, if you are just
            # looking for a specific file being created, you can place a check
            # in such function and if such file does exist you can make Cuckoo
            # terminate the analysis straight away.
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

    # The argument for script's invocation must be the shared folder where
    # Cuckoo will be able to get the analysis config file and write the
    # results back.
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
