# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import json
import logging
import collections
import threading

from datetime import datetime

from lib.common.exceptions import CuckooFridaError
from lib.common.utils import load_configs

try:
    import frida
    HAVE_FRIDA = True
except ImportError:
    HAVE_FRIDA = False

AGENT_PATH = "lib/core/agent.js"

log = logging.getLogger(__name__)


class PipeController(object):
    """Schedule handling of event messages on Frida's pipe."""

    def __init__(self):
        self._pending = collections.deque([])
        self._lock = threading.Lock()
        self._running = False
        self._worker = None

    def run(self):
        """Start the pipe controller."""
        self._running = True

        if not self._worker:
            self._worker = threading.Thread(target=self._run)
            self._worker.start()

    def _run(self):
        """Looper for the task queue."""
        while self._running:
            task = None
            with self._lock:
                if self._pending:
                    task = self._pending.popleft()
            if task:
                try:
                    task()
                except Exception as e:
                    log.error(e)

    def stop(self):
        """Stop the pipe controller."""
        self._running = False

        if self._worker:
            self._worker.join()

    def schedule(self, fn):
        """Schedule a new task on the pipe.
        @param fn: A function task.
        """
        with self._lock:
            self._pending.append(fn)

class Client(object):
    """Interface of Frida's client. Used for sample instrumentation.
    https://github.com/frida/frida
    """

    def __init__(self, analyzer):
        """@param analyzer: Analyzer instance.
        """
        if not HAVE_FRIDA:
            raise CuckooFridaError(
                "Failed to import Frida's Python bindings.. Check your guest "
                "installation."
            )

        self.pipe_ctrl = PipeController()

        self.processes = {}
        self.sessions = {}
        self.scripts = {}
        self.device = frida.get_local_device()

        self.device.on(
            "child-added",
            lambda child: self._on_child_added(child.pid)
        )
        self.device.on(
            "child-removed",
            lambda child: self._on_child_removed(child.pid)
        )

        self.agent_handler = AgentHandler(analyzer, self)

        self._on_child_added_callback = None
        self._on_child_removed_callback = None

    @property
    def on_child_added_callback(self):
        return self._on_child_added_callback

    @on_child_added_callback.setter
    def on_child_added_callback(self, callback):
        self._on_child_added_callback = callback

    @property
    def on_child_removed_callback(self):
        return self._on_child_removed_callback

    @on_child_removed_callback.setter
    def on_child_removed_callback(self, callback):
        self._on_child_removed_callback = callback

    def _add_process(self, pid):
        """Add a process to the list of processes.
        @param pid: Process id.
        """
        for proc in self.device.enumerate_processes():
            if proc.pid == pid:
                process_name = proc.name

        proc_info = self._get_agent(pid).call("getCurrentProcessInfo")
        self.processes[pid] = {
            "ppid": proc_info["ppid"],
            "uid": proc_info["uid"],
            "process_name": process_name,
            "first_seen": str(datetime.now()),
        }

    def spawn(self, pkg):
        """Start a target Android application.
        This is essentially a wrapper for a `frida.spawn` call.
        @param pkg: target application entry point.
        """
        try:
            pid = self.device.spawn(pkg)
            log.info("Target application package (%s) spawned.", pkg)
        except frida.NotSupportedError:
            raise CuckooFridaError(
                "No application with package name %s installed." % pkg
            )
        except frida.TimedOutError:
            raise CuckooFridaError("Timeout while spawning application.")
        except frida.TransportError:
            raise CuckooFridaError("Frida transport error, spawning failed.")

        return pid

    def _resume(self, pid):
        """Resume a suspended process.
        @param pid: Process id.
        """
        try:
            self.device.resume(pid)
            log.info("Process with id: %d is resumed" % pid)
        except (frida.InvalidArgumentError, frida.ProcessNotFoundError):
            log.warning(
                "Attempted to resume a non-resumable process %d." % pid
            )

    def _start_session(self, pid):
        """Initiate a frida session with a process.
        @param pid: Process id.
        """
        try:
            session = self.device.attach(pid)
            log.info("Frida session established!")
        except frida.ProcessNotFoundError:
            raise CuckooFridaError(
                "Failed to initiate a frida session with the application "
                "process: %s." % pid
            )

        session.enable_child_gating()
        self.sessions[pid] = session

    def _load_script(self, pid, filepath):
        """Inject a JS script into the process
        @param pid: Process id.
        @param filepath: Path to JS script file.'
        """
        if pid not in self.sessions:
            raise CuckooFridaError(
                "Cannot inject script into process, Frida is not attached."
            )

        try:
            with open(filepath, "r") as fd:
                s = self.sessions[pid]
                script = s.create_script(fd.read(), runtime='v8')

                def schedule_msg_rcv(message, payload):
                    handler = lambda: self.agent_handler.on_receive(message)
                    self.pipe_ctrl.schedule(handler)

                script.on("message", schedule_msg_rcv)
                script.load()
                self.scripts[pid] = script
            log.info("Script loaded successfully")
        except frida.TransportError:
            raise CuckooFridaError("Failed to inject instrumentation script")

    def _load_agent(self, pid):
        """Load the instrumentation agent into the process and start it.
        @param pid: Process id.
        """
        if not os.path.exists(AGENT_PATH):
            raise CuckooFridaError(
                "Agent script not found at '%s', unable to inject into "
                "process.." % AGENT_PATH
            )

        self._start_session(pid)
        self._load_script(pid, AGENT_PATH)
        self._add_process(pid)
        self.scripts[pid].exports.start(load_configs("config/"))

        self._resume(pid)

    def _get_agent(self, pid):
        """Get the agent injected in a process.
        @param pid: Process id.
        @return: Agent instance.
        """
        if pid not in self.scripts:
            return None

        return Agent(pid, self.scripts[pid])

    def _terminate_session(self, pid):
        """Terminate an attached session.
        @param pid: Process id.
        """
        if pid in self.processes:
            del self.processes[pid]

        if pid in self.scripts:
            try:
                self.scripts[pid].unload()
            except frida.InvalidOperationError:
                pass

            del self.scripts[pid]

        if pid in self.sessions:
            self.sessions[pid].detach()
            del self.sessions[pid]

        log.info("Frida session is terminated")

    def start(self, pid):
        """Start the Frida client on the given PID
        @param pid: Process id.
        """
        self.pipe_ctrl.run()
        self.pipe_ctrl.schedule(lambda: self._load_agent(pid))

    def abort(self):
        """Abort the Frida client."""
        # TODO: terminate frida sessions without breaking the instrumentation
        self.pipe_ctrl.stop()

    def _on_child_added(self, pid):
        """A callback function. Called when a new child is added.
        @param pid: Process id of child.
        """
        self.pipe_ctrl.schedule(lambda: self._load_agent(pid))

        if self._on_child_added_callback:
            self.pipe_ctrl.schedule(
                lambda: self._on_child_added_callback(pid)
            )

    def _on_child_removed(self, pid):
        """A callback function. Called when a child is removed.
        @param pid: Process id of child.
        """
        self.pipe_ctrl.schedule(lambda: self._terminate_session(pid))

        if self._on_child_removed_callback:
            self.pipe_ctrl.schedule(
                lambda: self._on_child_removed_callback(pid)
            )

class Agent(object):
    """RPC interface of Frida's agent."""

    def __init__(self, pid, script):
        """@param pid: Process id.
        @param script: Script object to communicate with agent.
        """
        self.pid = pid
        self.script = script

    def call(self, func_name, args=None):
        """Call an exported function from the agent script.
        @param func_name: Name of exported function.
        @param args: function arguments.
        """
        if args is not None and not isinstance(args, list):
            args = [args]

        return self.script.exports.api(func_name, args)

class AgentHandler(object):
    """Handles event messages received from a Frida agent."""

    def __init__(self, analyzer, client):
        """@param analyzer: Analyzer instance.
        @param client: Frida client instance.
        """
        self.client = client
        self.analyzer = analyzer
        self.loggers = {}

    def on_receive(self, message):
        """A callback function invoked upon receiving an event message
        from Frida's agent.
        """
        if message["type"] == "send":
            if "payload" in message:
                split_msg = message["payload"].splitlines()
                header = split_msg[0]
                message = "\n".join(split_msg[1:])

                # Determine handler based on event type..
                handler = getattr(self, "_handle_%s" % header, None)
                if handler:
                    handler(message)
        elif message["type"] == "error":
            self._log_event(-1, "errors", message)

    def _log_event(self, pid, event_type, data):
        """Log an event to log file.
        @param pid: Process id (event source).
        @param event_type: Type of event.
        @param data: Event data.
        """
        if pid != -1:
            event_id = "%s.%s" % (pid, event_type)
        else:
            event_id = event_type

        if event_id not in self.loggers:
            logger = logging.getLogger(event_id)
            logger.setLevel(logging.DEBUG)
            logger.propagate = False

            filepath = self.analyzer.logs.add_log(event_id)
            fh = logging.FileHandler(filepath)
            fh.setFormatter(logging.Formatter("%(message)s"))
            logger.addHandler(fh)

            self.loggers[event_id] = logger
            
            if pid in self.client.processes:
                logger.info(json.dumps(self.client.processes[pid]))

        self.loggers[event_id].info(data)

    def _handle_jvmHook(self, message):
        """Handle jvmHook events."""
        pid, api_call = message.splitlines()
        self._log_event(int(pid), "jvmHook", api_call)

    def _handle_filemon(self, event_type, pid, data):
        """Generic handler for file operations."""
        event_data = {}
        event_data[event_type] = data
        self._log_event(int(pid), "filemon", json.dumps(event_data))

    def _handle_fileRead(self, message):
        """Handle fileRead events."""
        pid, filepath = message.splitlines()
        self._handle_filemon("file_read", pid, filepath)

    def _handle_fileWrite(self, message):
        """Handle fileWrite events."""
        pid, filepath = message.splitlines()
        self._handle_filemon("file_written", pid, filepath)

    def _handle_fileCreate(self, message):
        """Handle fileCreate events."""
        pid, filepath = message.splitlines()
        self.analyzer.files.add_file(filepath)
        self._handle_filemon("file_created", pid, filepath)

    def _handle_fileDelete(self, message):
        """Handle fileDelete events."""
        pid, filepath = message.splitlines()
        self._handle_filemon("file_deleted", pid, filepath)

    def _handle_fileMove(self, message):
        """Handle fileMove events."""
        pid, arg = message.splitlines()
        oldfilepath, newfilepath = arg.split(",")
        self.analyzer.files.move_file(oldfilepath, newfilepath)
        self._handle_filemon("file_moved", pid, (oldfilepath, newfilepath))
