# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import json
import logging

from lib.common.exceptions import CuckooFridaError
from lib.common.utils import load_configs

try:
    import frida
    HAVE_FRIDA = True
except ImportError:
    HAVE_FRIDA = False

AGENT_PATH = "lib/core/agent.js"

log = logging.getLogger(__name__)

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

        self.agent_handler = AgentHandler(analyzer)

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

    def load_agent(self, pid):
        """Load our instrumentation agent into the process and start it.
        @param pid: Target process.
        """
        if not os.path.exists(AGENT_PATH):
            raise CuckooFridaError(
                "Agent script not found at '%s', unable to inject into "
                "process.." % AGENT_PATH
            )

        self._start_session(pid)
        self._load_script(pid, AGENT_PATH)
        self.scripts[pid].exports.start(load_configs("config/"))

        self._resume(pid)

    def terminate_session(self, pid):
        """Terminate an attached session.
        @param pid: process id.
        """
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

    def _on_child_added(self, pid):
        """A callback function. Called when a new child is added.
        @param pid: PID of child process.
        """
        if self._on_child_added_callback:
            self._on_child_added_callback(pid)

    def _on_child_removed(self, pid):
        """A callback function. Called when a child is removed.
        @param pid: PID of child process.
        """
        if pid in self.sessions:
            del self.sessions[pid]
        
        if pid in self.scripts:
            del self.sessions[pid]
        
        if self._on_child_removed_callback:
            self._on_child_removed_callback(pid)

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
        """Initiate a frida session with the application
        @param pid: Process id.
        """
        try:
            session = self.device.attach(pid)
            log.info("Frida session established!")
        except frida.ProcessNotFoundError:
            raise CuckooFridaError(
                "Failed to initiate a frida session with the application "
                "process."
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
                script.on("message", self.agent_handler.on_receive)
                script.load()
                self.scripts[pid] = script
            log.info("Script loaded successfully")
        except frida.TransportError:
            raise CuckooFridaError("Failed to inject instrumentation script")

class AgentHandler(object):
    """Handles event messages received from Frida's agent."""

    def __init__(self, analyzer):
        """@param analyzer: Analyzer instance.
        """
        self.analyzer = analyzer
        self.loggers = {}

    def on_receive(self, message, payload):
        """A callback function invoked upon receiving an event message
        from Frida's agent.
        """
        if message["type"] == "send":
            if "payload" in message:
                split_msg = message["payload"].splitlines()
                header = split_msg[0]
                message = "\n".join(split_msg[1:])

                # Determine handler based on event..
                handler = getattr(self, "_handle_%s" % header, None)
                if handler:
                    handler(message)
        elif message["type"] == "error":
            self.log_event("errors", message)

    def log_event(self, src, data):
        """Log an event to log file.
        @param src: source of event.
        @param data: event data.
        """
        if src not in self.loggers:
            logger = logging.getLogger(src)
            logger.setLevel(logging.DEBUG)
            logger.propagate = False

            filepath = self.analyzer.logs.add_log(src)
            fh = logging.FileHandler(filepath)
            fh.setFormatter(logging.Formatter("%(message)s"))
            logger.addHandler(fh)

            self.loggers[src] = logger

        self.loggers[src].info(data)

    def _handle_jvmHook(self, message):
        """Handle jvmHook events."""
        pid, api_call = message.splitlines()
        self.log_event("jvmHook_" + pid, api_call)

    def _handle_fileDrop(self, message):
        """Handle fileDrop events."""
        self.analyzer.files.add_file(message)

    def _handle_fileDelete(self, message):
        """Handle fileDelete events."""
        self.analyzer.files.add_file(message)

    def _handle_fileMove(self, message):
        """Handle fileMove events."""
        oldfilepath, newfilepath = message.split(",")
        self.analyzer.files.move_file(oldfilepath, newfilepath)
