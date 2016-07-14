# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import copy
import logging.handlers
import os.path
import thread

from lib.cuckoo.common.colors import red, yellow, cyan
from lib.cuckoo.core.database import Database
from lib.cuckoo.common.constants import CUCKOO_ROOT

_tasks = {}

class DatabaseHandler(logging.Handler):
    """Logging to database handler.
    Used to log errors related to tasks in database.
    """

    def emit(self, record):
        if hasattr(record, "task_id"):
            db = Database()
            db.add_error(self.format(record), int(record.task_id))

class TaskHandler(logging.Handler):
    """Per-task logger.
    Used to log all task specific events to a per-task cuckoo.log log file.
    """

    def emit(self, record):
        task_id = _tasks.get(thread.get_ident())
        if not task_id:
            return

        # Don't bother, this will be improved with #863 anyway.
        logpath = os.path.join(
            CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "cuckoo.log"
        )

        with open(logpath, "a+b") as f:
            f.write("%s\n" % self.format(record))

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

def task_log_start(task_id):
    """Associate a thread with a task."""
    _tasks[thread.get_ident()] = task_id

def task_log_stop(task_id):
    """Disassociate a thread from a task."""
    _tasks.pop(thread.get_ident(), None)
