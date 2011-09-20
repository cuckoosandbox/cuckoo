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

from cuckoo.core.config import *
from cuckoo.core.logging import *
from cuckoo.core.now import *

try:
    import sqlite3
except ImportError:
    log("[Database] Unable to locate Python SQLite3 module. Please " \
        "verify your installation. Exiting...", "ERROR")
    sys.exit(-1)

class CuckooDatabase:
    def __init__(self):
        self.db_file = CuckooConfig().get_localdb()
        self._conn = None
        self._cursor = None

        # Check if SQLite database already exists. If it doesn't exist I invoke
        # the generation procedure.
        if not os.path.exists(self.db_file):
            if self._generate():
                log("[Database] [Init] Generated database \"%s\" which didn't" \
                    " exist before." % self.db_file, "INFO")                

        # Once the database is generated of it already has been, I can
        # initialize the connection.
        try:
            self._conn = sqlite3.connect(self.db_file)
            self._cursor = self._conn.cursor()
        except Exception, why:
            log("[Database] [Init] Unable connection to DB \"%s\": %s."
                % (self.db_file, why), "ERROR")

        log("[Database] [Init] Connected to SQLite database \"%s\"." %
            self.db_file, "DEBUG")

    def _generate(self):
        if os.path.exists(self.db_file):
            return False

        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        cursor.execute("CREATE TABLE queue (\n"               \
                       "  id INTEGER PRIMARY KEY,\n"          \
                       "  md5 TEXT DEFAULT NULL,\n"           \
                       "  target TEXT NOT NULL,\n"            \
                       "  timeout INTEGER DEFAULT NULL,\n"    \
                       "  priority INTEGER DEFAULT 0,\n"      \
                       "  added_on DATE DEFAULT NULL,\n"      \
                       "  completed_on DATE DEFAULT NULL,\n"  \
                       "  package TEXT DEFAULT NULL,\n"       \
                       "  lock INTEGER DEFAULT 0,\n"          \
                       # Status possible values:
                       #   0 = not completed
                       #   1 = completed successfully
                       #   2 = error occurred.
                       "  status INTEGER DEFAULT 0,\n"        \
                       "  custom TEXT DEFAULT NULL\n"         \
                       ");")

        return True

    def get_task(self):
        if not self._cursor:
            log("[Database] [Get Task] Unable to acquire cursor.",
                "ERROR")
            return None

        # Select one item from the queue table with higher priority and older
        # addition date which has not already been processed.
        try:        
            self._cursor.execute("SELECT * FROM queue "  \
                                 "WHERE lock = 0 "       \
                                 "AND status = 0 "       \
                                 "ORDER BY priority, added_on LIMIT 1;")
        except sqlite3.OperationalError, why:
            log("[Database] [Get Task] Unable to query database: %s."
                % why, "ERROR")
            return None

        task_row = self._cursor.fetchone()

        if task_row:
            task = {}
            task["id"] = task_row[0]
            task["md5"] = task_row[1]
            task["target"] = task_row[2]
            task["timeout"] = task_row[3]
            task["priority"] = task_row[4]
            task["added_on"] = task_row[5]
            task["completed_on"] = task_row[6]
            task["package"] = task_row[7]
            task["lock"] = task_row[8]
            task["status"] = task_row[9]
            task["custom"] = task_row[10]

            return task
        else:
            return None

    def lock(self, task_id):
        if not self._cursor:
            log("[Database] [Lock] Unable to acquire cursor.",
                "ERROR")
            return False

        # Check if specified task does actually exist in the database.
        try:
            self._cursor.execute("SELECT id FROM queue WHERE id = %s;" % task_id)
            task_row = self._cursor.fetchone()
        except sqlite3.OperationalError, why:
            log("[Database] [Lock] Unable to query database: %s." % why,
                "ERROR")
            return False

        # If task exists lock it, so that it doesn't get processed again.
        if task_row:
            try:
                self._cursor.execute("UPDATE queue SET lock = 1 WHERE id = %s;"
                                    % task_id)
                self._conn.commit()
            except sqlite3.OperationalError, why:
                log("[Database] [Lock] Unable to query database: %s." % why,
                    "ERROR")
                return False
        else:
            log("[Database] [Lock] No entries for task with id %s." % task_id,
                "WARNING")
            return False

        log("[Database] [Lock] Locked task with id %s." % task_id)

        return True

    def unlock(self, task_id):
        if not self._cursor:
            log("[Database] [Unlock] Unable to acquire cursor.",
                "ERROR")
            return False

        # Check if specified task does actually exist in the database.
        try:
            self._cursor.execute("SELECT id FROM queue WHERE id = %s;" % task_id)
            task_row = self._cursor.fetchone()
        except sqlite3.OperationalError, why:
            log("[Database] [Unlock] Unable to query database: %s." % why,
                "ERROR")
            return False

        # If task exists unlock it, in this case it's probably meant to be
        # rescheduled for another analysis procedure.
        if task_row:
            try:
                self._cursor.execute("UPDATE queue SET lock = 0 WHERE id = %s;"
                                    % task_id)
                self._conn.commit()
            except sqlite3.OperationalError, why:
                log("[Database] [Unlock] Unable to query database: %s." % why,
                    "ERROR")
                return False
        else:
            log("[Database] [Unlock] No entries for task with id %s." % task_id,
                "WARNING")
            return False

        log("[Database] [Unlock] Unlocked task with id %s." % task_id)

        return True

    def complete(self, task_id, success = True):
        if not self._cursor:
            log("[Database] [Complete] Unable to acquire cursor.",
                "ERROR")
            return False

        # Check if specified task does actually exist in the database.
        try:
            self._cursor.execute("SELECT id FROM queue WHERE id = %s;" % task_id)
            task_row = self._cursor.fetchone()
        except sqlite3.OperationalError, why:
            log("[Database] [Complete] Unable to query database: %s." % why,
                "ERROR")
            return False

        # If task exists proceed with update process.
        if task_row:
            # Check if the task was completed successfully or not.
            if success:
                status = 1 # Success
            else:
                status = 2 # Failure

            try:
                self._cursor.execute("UPDATE queue SET lock = 0, "     \
                                    "status = %s, "                   \
                                    "completed_on = \"%s\" "          \
                                    "WHERE id = %s;"
                                    % (status, get_now(), task_id))
                self._conn.commit()
            except sqlite3.OperationalError, why:
                log("[Database] [Complete] Unable to query database: %s." % why,
                    "ERROR")
                return False
        else:
            log("[Database] [Complete] No entries for task with id %s."
                % task_id, "WARNING")
            return False

        log("[Database] [Complete] Task with id %s updated in the database " \
            "with status \"%s\"." % (task_id, status))

        return True
