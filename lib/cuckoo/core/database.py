# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import sqlite3

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooDatabaseError
from lib.cuckoo.common.abstracts import Dictionary

class Database:
    """Analysis queue database."""

    def __init__(self, root="."):
        """@param root: database path."""
        self.db_file = os.path.join(root, os.path.join(CUCKOO_ROOT, "db", "cuckoo.db"))

        self.generate()
        self.conn = sqlite3.connect(self.db_file, timeout=60)
        self.cursor = self.conn.cursor()

    def generate(self):
        """Create database.
        @return: operation status.
        """
        if os.path.exists(self.db_file):
            return False

        db_dir = os.path.dirname(self.db_file)
        if not os.path.exists(db_dir):
            try:
                os.makedirs(db_dir)
            except OSError as e:
                return False

        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        try:
            cursor.execute("CREATE TABLE tasks (\n"                         \
                           "    id INTEGER PRIMARY KEY,\n"                  \
                           "    md5 TEXT DEFAULT NULL,\n"                   \
                           "    file_path TEXT NOT NULL,\n"                 \
                           "    timeout INTEGER DEFAULT NULL,\n"            \
                           "    priority INTEGER DEFAULT 0,\n"              \
                           "    custom TEXT DEFAULT NULL,\n"                \
                           "    machine TEXT DEFAULT NULL,\n"               \
                           "    package TEXT DEFAULT NULL,\n"               \
                           "    options TEXT DEFAULT NULL,\n"               \
                           "    platform TEXT DEFAULT NULL,\n"              \
                           "    added_on DATE DEFAULT CURRENT_TIMESTAMP,\n" \
                           "    completed_on DATE DEFAULT NULL,\n"          \
                           "    lock INTEGER DEFAULT 0,\n"                  \
                           # Status possible values:
                           #   0 = not completed
                           #   1 = error occurred
                           #   2 = completed successfully.
                           "    status INTEGER DEFAULT 0\n"                 \
                           ");")
        except sqlite3.OperationalError as e:
            raise CuckooDatabaseError("Unable to create database: %s" % e)

        return True

    def dictify(self, row):
        """Transform a database row in a dict.
        @param row: database row.
        @return: dict.
        """
        try:
            task = Dictionary()
            task.id = row[0]
            task.md5 = row[1]
            task.file_path = row[2]
            task.timeout = row[3]
            task.priority = row[4]
            task.custom = row[5]
            task.machine = row[6]
            task.package = row[7]
            task.options = row[8]
            task.platform = row[9]
            task.added_on = row[10]
            task.completed_on = row[11]
            task.lock = row[12]
            task.status = row[13]
        except IndexError as e:
            print e
            return None

        return task

    def add(self,
            file_path,
            md5=None,
            timeout=None,
            package=None,
            options=None,
            priority=None,
            custom=None,
            machine=None,
            platform=None):
        """Add a task to database.
        @param file_path: sample path.
        @param md5: sample MD5.
        @param timeout: selected timeout.
        @param options: analysis options.
        @param priority: analysis priority.
        @param custom: custom options.
        @param machine: selected machine.
        @param platform: platform
        @return: cursor or None.
        """
        if not file_path or not os.path.exists(file_path):
            return None

        try:
            self.cursor.execute("INSERT INTO tasks " \
                                "(file_path, md5, timeout, package, options, priority, custom, machine, platform) " \
                                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);",
                                (file_path, md5, timeout, package, options, priority, custom, machine, platform))
            self.conn.commit()
            return self.cursor.lastrowid
        except sqlite3.OperationalError as e:
            return None

    def fetch(self):
        """Fetch a task.
        @return: task dict or None.
        """
        try:
            self.cursor.execute("SELECT * FROM tasks " \
                                "WHERE lock = 0 "      \
                                "AND status = 0 "      \
                                "ORDER BY priority, added_on LIMIT 1;")
        except sqlite3.OperationalError as e:
            print e
            return None

        row = self.cursor.fetchone()

        if row:
            return self.dictify(row)
        else:
            return None

    def lock(self, task_id):
        """Lock a task.
        @param task_id: task id.
        @return: operation status.
        """
        try:
            self.cursor.execute("SELECT id FROM tasks WHERE id = ?;",
                                (task_id,))
            row = self.cursor.fetchone()
        except sqlite3.OperationalError as e:
            return False

        if row:
            try:
                self.cursor.execute("UPDATE tasks SET lock = 1 WHERE id = ?;",
                                    (task_id,))
                self.conn.commit()
            except sqlite3.OperationalError as e:
                return False
        else:
            return False

        return True

    def unlock(self, task_id):
        """Unlock a task.
        @param task_id: task id.
        @return: operation status.
        """
        try:
            self.cursor.execute("SELECT id FROM tasks WHERE id = ?;",
                                (task_id,))
            row = self.cursor.fetchone()
        except sqlite3.OperationalError as e:
            return False

        if row:
            try:
                self.cursor.execute("UPDATE tasks SET lock = 0 WHERE id = ?;",
                                    (task_id,))
                self.conn.commit()
            except sqlite3.OperationalError as e:
                return False
        else:
            return False

        return True

    def complete(self, task_id, success=True):
        """Mark a task as completed.
        @param task_id: task id.
        @param success: completed with status.
        @return: operation status.
        """
        try:
            self.cursor.execute("SELECT id FROM tasks WHERE id = ?;",
                                (task_id,))
            row = self.cursor.fetchone()
        except sqlite3.OperationalError as e:
            return False

        if row:
            if success:
                status = 2
            else:
                status = 1

            try:
                self.cursor.execute("UPDATE tasks SET lock = 0, "     \
                                    "status = ?, "                    \
                                    "completed_on = DATETIME('now') " \
                                    "WHERE id = ?;", (status, task_id))
                self.conn.commit()
            except sqlite3.OperationalError as e:
                return False
        else:
            return False

        return True
