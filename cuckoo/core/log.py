# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import copy
import gevent.thread
import json
import logging
import logging.handlers
import thread
import time

from cuckoo.common.colors import red, yellow, cyan
from cuckoo.core.database import Database
from cuckoo.misc import cwd

_tasks = {}
_loggers = {}

# Current GMT+x.
if time.localtime().tm_isdst:
    tz = time.altzone / -3600.
else:
    tz = time.timezone / -3600.

# The greenlet library (used by Gevent) also creates some state per thread,
# so we can (ab)use this for both multi-threading and Gevent code
task_key = gevent.thread.get_ident

class DatabaseHandler(logging.Handler):
    """Logging to database handler.
    Used to log errors related to tasks in database.
    """

    def emit(self, record):
        # TODO Should this also attempt to guess the task ID from _tasks?
        if hasattr(record, "task_id"):
            Database().add_error(
                self.format(record), int(record.task_id),
                getattr(record, "error_action", None)
            )

class TaskHandler(logging.Handler):
    """Per-task logger.
    Used to log all task specific events to a per-task cuckoo.log log file.
    """

    def emit(self, record):
        task = _tasks.get(task_key())
        if not task:
            return

        task[1].write("%s\n" % self.format(record))

class ConsoleHandler(logging.StreamHandler):
    """Logging to console handler."""

    def emit(self, record):
        colored = copy.copy(record)

        if record.levelname == "WARNING":
            colored.msg = yellow(record.msg)
        elif record.levelname == "ERROR" or record.levelname == "CRITICAL":
            colored.msg = red(record.msg)
        else:
            if "analysis procedure completed" in record.msg:
                colored.msg = cyan(record.msg)
            else:
                colored.msg = record.msg

        logging.StreamHandler.emit(self, colored)

class JsonFormatter(logging.Formatter):
    """Logging Cuckoo logs to JSON."""

    def format(self, record):
        action = record.__dict__.get("action")
        status = record.__dict__.get("status")
        task = _tasks.get(task_key())
        task_id = task[0] if task else record.__dict__.get("task_id")
        d = {
            "action": action,
            "task_id": task_id,
            "status": status,
            "time": record.created,
            "level": record.levelname.lower(),
            "message": record.getMessage(),
        }
        base = logging.makeLogRecord({})
        for key, value in record.__dict__.items():
            if key not in base.__dict__:
                d[key] = value
        return json.dumps(d)

    def filter(self, record):
        action = record.__dict__.get("action")
        status = record.__dict__.get("status")
        return action and status

def task_log_start(task_id):
    """Associate a thread with a task."""
    fp = open(cwd("cuckoo.log", analysis=task_id), "a+b")
    _tasks[task_key()] = (task_id, fp)

def task_log_stop(task_id):
    """Disassociate a thread from a task."""
    task = _tasks.pop(task_key(), None)
    if task:
        task[1].close()

def init_logger(name, level=None):
    formatter = logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
    )

    if name == "cuckoo.log":
        l = logging.handlers.WatchedFileHandler(cwd("log", "cuckoo.log"))
        l.setFormatter(formatter)
        l.setLevel(level)

    if name == "cuckoo.json":
        j = JsonFormatter()
        l = logging.handlers.WatchedFileHandler(cwd("log", "cuckoo.json"))
        l.setFormatter(j)
        l.addFilter(j)

    if name == "console":
        l = ConsoleHandler()
        l.setFormatter(formatter)
        l.setLevel(level)

    if name == "database":
        l = DatabaseHandler()
        l.setLevel(logging.ERROR)

    if name == "task":
        l = TaskHandler()
        l.setFormatter(formatter)

    if name.startswith("process-") and name.endswith(".json"):
        j = JsonFormatter()
        l = logging.handlers.WatchedFileHandler(cwd("log", name))
        l.setFormatter(j)
        l.addFilter(j)

    _loggers[name] = l
    logging.getLogger().addHandler(l)

def logger(message, *args, **kwargs):
    """Log a message to specific logger instance."""
    logfile = kwargs.pop("logfile", None)
    record = logging.LogRecord(
        None, logging.INFO, None, None, message, args, None, None
    )
    record.asctime = "%s,%03d" % (
        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(record.created)),
        record.msecs
    )
    record.message = record.getMessage()
    record.__dict__.update(kwargs)

    for key, value in _loggers.items():
        if logfile and key == logfile:
            value.handle(record)
        if logfile is None and key.endswith(".json"):
            value.handle(record)
