import os
import sys
import sqlite3

from lib.cuckoo.abstract.dictionary import Dictionary

class Database:
    def __init__(self, root="."):
        self.db_file = os.path.join(root, "db/cuckoo.db")

        self.generate()
        self.conn = sqlite3.connect(self.db_file)
        self.cursor = self.conn.cursor()

    def generate(self):
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
                           "    platform TEXT DEFAULT NULL,\n"              \
                           "    added_on DATE DEFAULT CURRENT_TIMESTAMP,\n" \
                           "    completed_on DATE DEFAULT NULL,\n"          \
                           "    lock INTEGER DEFAULT 0,\n"                  \
                           # Status possible values:
                           #   0 = not completed
                           #   1 = completed successfully
                           #   2 = error occurred.
                           "    status INTEGER DEFAULT 0\n"                 \
                           ");")
        except sqlite3.OperationalError as e:
            sys.exit("Unable to create database: %s" % e)

        return True

    def dictify(self, row):
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
            task.platform = row[8]
            task.added_on = row[9]
            task.completed_on = row[10]
            task.lock = row[11]
            task.status = row[12]
        except IndexError as e:
            print e
            return None

        return task

    def add(self,
            file_path,
            md5=None,
            timeout=None,
            package=None,
            priority=None,
            custom=None,
            machine=None):
        if not file_path or not os.path.exists(file_path):
            return None

        try:
            self.cursor.execute("INSERT INTO tasks " \
                                "(file_path, md5, timeout, package, priority, custom, machine) " \
                                "VALUES (?, ?, ?, ?, ?, ?, ?);",
                                (file_path, md5, timeout, package, priority, custom, machine))
            self.conn.commit()
            return self.cursor.lastrowid
        except sqlite3.OperationalError as e:
            return None

    def fetch(self):
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
        try:
            self.cursor.execute("SELECT id FROM tasks WHERE id = ?;",
                                (task_id,))
            row = self.cursor.fetchone()
        except sqlite3.OperationalError as e:
            return False

        if row:
            if success:
                status = 1
            else:
                status = 2

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
