# Cuckoo Sandbox - Automated Malware Analysis
# Copyright (C) 2010-2012  Claudio "nex" Guarnieri (nex@cuckoobox.org)
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
import logging

from cuckoo.config.config import CuckooConfig
from cuckoo.config.constants import CUCKOO_DB_FILE

try:
    import sqlite3
except ImportError:
    sys.stderr.write("ERROR: Unable to locate Python SQLite3 module. " \
                     "Please verify your installation. Exiting...\n")
    sys.exit(-1)

class CuckooDatabase:
    """
    Database abstraction layer.
    """
    def __init__(self):
        log = logging.getLogger("Database.Init")
        self._conn = None
        self._cursor = None

        # Check if SQLite database already exists. If it doesn't exist I invoke
        # the generation procedure.
        if not os.path.exists(CUCKOO_DB_FILE):
            if self._generate():
                log.info("Generated database \"%s\" which didn't" \
                         " exist before." % CUCKOO_DB_FILE)
            else:
                log.error("Unable to generate database")

        # Once the database is generated of it already has been, I can
        # initialize the connection.
        try:
            self._conn = sqlite3.connect(CUCKOO_DB_FILE)
            self._cursor = self._conn.cursor()
        except Exception, why:
            log.error("Unable to connect to database \"%s\": %s."
                      % (CUCKOO_DB_FILE, why))

        log.debug("Connected to SQLite database \"%s\"." % CUCKOO_DB_FILE)

    def _generate(self):
        """
        Creates database structure in a SQLite file.
        """
        if os.path.exists(CUCKOO_DB_FILE):
            return False

        db_dir = os.path.dirname(CUCKOO_DB_FILE)
        if not os.path.exists(db_dir):
            try:
                os.makedirs(db_dir)
            except (IOError, os.error), why:
                log.error("Something went wrong while creating database " \
                          "directory \"%s\": %s" % (db_dir, why))
                return False

        conn = sqlite3.connect(CUCKOO_DB_FILE)
        cursor = conn.cursor()

        cursor.execute("CREATE TABLE queue (\n"                            \
                       "  id INTEGER PRIMARY KEY,\n"                       \
                       "  md5 TEXT DEFAULT NULL,\n"                        \
                       "  target TEXT NOT NULL,\n"                         \
                       "  timeout INTEGER DEFAULT NULL,\n"                 \
                       "  priority INTEGER DEFAULT 0,\n"                   \
                       "  added_on DATE DEFAULT CURRENT_TIMESTAMP,\n"      \
                       "  completed_on DATE DEFAULT NULL,\n"               \
                       "  package TEXT DEFAULT NULL,\n"                    \
                       "  lock INTEGER DEFAULT 0,\n"                       \
                       # Status possible values:
                       #   0 = not completed
                       #   1 = completed successfully
                       #   2 = error occurred.
                       "  status INTEGER DEFAULT 0,\n"                     \
                       "  custom TEXT DEFAULT NULL,\n"                      \
                       "  vm_id TEXT DEFAULT NULL\n"                       \
                       ");")

        return True

    def _get_task_dict(self, row):
        try:
            task = {}
            task["id"] = row[0]
            task["md5"] = row[1]
            task["target"] = row[2]
            task["timeout"] = row[3]
            task["priority"] = row[4]
            task["added_on"] = row[5]
            task["completed_on"] = row[6]
            task["package"] = row[7]
            task["lock"] = row[8]
            task["status"] = row[9]
            task["custom"] = row[10]
            task["vm_id"] = row[11]

            return task
        except Exception, why:
            return None

    def add_task(self, target, md5 = None, timeout = None, package = None, priority = None, custom = None, vm_id = None):
        """
        Adds a new task to the database.
        @param target: database file path
        @param timeout: analysis timeout
        @param package: analysis package
        @param priority: analysis priority
        @param custom: value passed to processor
        @param vm_id: ID of virtual machine where run the analysis on
        @return: return ID of the newly generated tas
        """
        task_id = None

        if not self._cursor:
            return None

        if not target or target == "":
            return None

        try:
            self._cursor.execute("INSERT INTO queue " \
                                 "(target, md5, timeout, package, priority, custom, vm_id) " \
                                 "VALUES (?, ?, ?, ?, ?, ?, ?);",
                                 (target, md5, timeout, package, priority, custom, vm_id))
            self._conn.commit()
            task_id = self._cursor.lastrowid
        except sqlite3.OperationalError, why:
            return None

        return task_id

    def get_task(self):
        """
        Gets a task from pending queue.
        """
        log = logging.getLogger("Database.GetTask")

        if not self._cursor:
            log.error("Unable to acquire cursor.")
            return None

        # Select one item from the queue table with higher priority and older
        # addition date which has not already been processed.
        try:        
            self._cursor.execute("SELECT * FROM queue " \
                                 "WHERE lock = 0 " \
                                 "AND status = 0 " \
                                 "ORDER BY priority, added_on LIMIT 1;")
        except sqlite3.OperationalError, why:
            log.error("Unable to query database: %s." % why)
            return None

        task_row = self._cursor.fetchone()

        if task_row:
            return self._get_task_dict(task_row)
        else:
            return None

    def lock(self, task_id):
        """
        Locks a task.
        @param task_id: task id 
        """
        log = logging.getLogger("Database.Lock")

        if not self._cursor:
            log.error("Unable to acquire cursor.")
            return False

        # Check if specified task does actually exist in the database.
        try:
            self._cursor.execute("SELECT id FROM queue WHERE id = ?;",
                                 (task_id,))
            task_row = self._cursor.fetchone()
        except sqlite3.OperationalError, why:
            log.error("Unable to query database: %s." % why)
            return False

        # If task exists lock it, so that it doesn't get processed again.
        if task_row:
            try:
                self._cursor.execute("UPDATE queue SET lock = 1 WHERE id = ?;",
                                     (task_id,))
                self._conn.commit()
            except sqlite3.OperationalError, why:
                log.error("Unable to update database: %s." % why)
                return False
        else:
            log.warning("No entries for task with ID %s." % task_id)
            return False

        log.debug("Locked task with ID %d." % task_id)

        return True

    def unlock(self, task_id):
        """
        Unlocks a task.
        @param task_id: task id
        """ 
        log = logging.getLogger("Database.Unlock")

        if not self._cursor:
            log.error("Unable to acquire cursor.")
            return False

        # Check if specified task does actually exist in the database.
        try:
            self._cursor.execute("SELECT id FROM queue WHERE id = ?;",
                                 (task_id,))
            task_row = self._cursor.fetchone()
        except sqlite3.OperationalError, why:
            log.error("Unable to query database: %s." % why)
            return False

        # If task exists unlock it, in this case it's probably meant to be
        # rescheduled for another analysis procedure.
        if task_row:
            try:
                self._cursor.execute("UPDATE queue SET lock = 0 WHERE id = ?;",
                                     (task_id,))
                self._conn.commit()
            except sqlite3.OperationalError, why:
                log.error("Unable to update database: %s." % why)
                return False
        else:
            log.warning("No entries for task with ID %s." % task_id)
            return False

        log.debug("Unlocked task with id %s." % task_id)

        return True

    def complete(self, task_id, success = True):
        """
        Marks a task as ended.
        @param task_id: completed task id
        @param success: if task completed successfully
        """ 
        log = logging.getLogger("Database.Complete")

        if not self._cursor:
            log("Unable to acquire cursor.")
            return False

        # Check if specified task does actually exist in the database.
        try:
            self._cursor.execute("SELECT id FROM queue WHERE id = ?;",
                                 (task_id,))
            task_row = self._cursor.fetchone()
        except sqlite3.OperationalError, why:
            log.error("Unable to query database: %s." % why)
            return False

        # If task exists proceed with update process.
        if task_row:
            # Check if the task was completed successfully or not.
            if success:
                status = 1 # Success
            else:
                status = 2 # Failure

            try:
                self._cursor.execute("UPDATE queue SET lock = 0, " \
                                     "status = ?, " \
                                     "completed_on = DATETIME('now') " \
                                     "WHERE id = ?;",
                                     (status, task_id))
                self._conn.commit()
            except sqlite3.OperationalError, why:
                log.error("Unable to update database: %s." % why)
                return False
        else:
            log.warning("No entries for task with ID %d." % task_id)
            return False

        log.debug("Task with ID %s updated to status \"%s\"."
                       % (task_id, status))

        return True

    def search_tasks(self, md5):
        """
        Searches tasks by MD5.
        @param md5: MD5 hash of the analyzed files to search for
        @return: list of tasks matching the parameters
        """
        if not self._cursor:
            return None

        if not md5 or len(md5) != 32:
            return None

        try:
            self._cursor.execute("SELECT * FROM queue " \
                                 "WHERE md5 = ? " \
                                 "AND status = 1 " \
                                 "ORDER BY added_on DESC;",
                                 (md5,))
        except sqlite3.OperationalError, why:
            return None

        tasks = []
        for row in self._cursor.fetchall():
            task_dict = self._get_task_dict(row)
            if task_dict:
                tasks.append(task_dict)

        return tasks

    def completed_tasks(self, limit = None):
        """
        Retrieves a list of all completed analysis.
        @return: list of all completed tasks
        """

        if not self._cursor:
            return None

        try:
            sql = "SELECT * FROM queue " \
                  "WHERE status = 1 " \
                  "ORDER BY added_on DESC"
            if limit and limit > 0:
                sql += " LIMIT %s;" % limit
            self._cursor.execute(sql)
        except sqlite3.OperationalError, why:
            return None

        tasks = []
        for row in self._cursor.fetchall():
            task_dict = self._get_task_dict(row)
            if task_dict:
                tasks.append(task_dict)

        return tasks
