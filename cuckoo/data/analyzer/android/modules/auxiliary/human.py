# Copyright (C) 2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import random
import tempfile
import subprocess
import logging
import threading
import xml.etree.ElementTree as ET

from lib.common.utils import random_str, etree_compare
from lib.common.abstracts import Auxiliary

log = logging.getLogger(__name__)

def _tap(x, y):
    """Generate a tap event.
    @param x: x-axis coordinate.
    @param y: y-axis coordinate.
    """
    try:
        args = [
            "/system/bin/sh",
            "/system/bin/input",
            "tap", x, y
        ]
        p = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        _, err = p.communicate()
        if p.returncode:
            raise OSError(err)
    except OSError as e:
        log.error("Failed to generate touch event: %s", e)

def _input_text(text):
    """Input text event.
    @param text: str text input.
    """
    try:
        args = [
            "/system/bin/sh", 
            "/system/bin/input", 
            "text", text
        ]
        p = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        _, err = p.communicate()
        if p.returncode:
            raise OSError(err)
    except OSError as e:
        log.error("Failed to generate text event: %s", e)

class Human(threading.Thread, Auxiliary):
    """Generates random UI events."""

    def __init__(self, options={}):
        Auxiliary.__init__(self, options)
        threading.Thread.__init__(self)

        self.package = options.get("apk_entry", ":").split(":")[0]
        self.do_run = True
        self.window_dumps = []
        self.temp_dumpfile = None

    def _dump_views(self):
        """Dump the views in the current window with uiautomator."""
        try:
            args = [
                "/system/bin/sh",
                "/system/bin/uiautomator",
                "dump", self.temp_dumpfile
            ]
            p = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            _, err = p.communicate()
            if p.returncode:
                raise OSError(err)
        except OSError as e:
            log.error("Failed to dump window's views: %s", e)

    def _add_window_dump(self, tree):
        """Add a new views dump to the list.
        @param tree: layout tree node.
        """
        for d in self.window_dumps:
            ignore_attrib_keys = ["checked", "focused", "selected"]
            if etree_compare(d["tree"], tree, ignore_attrib_keys):
                return d

        new_dump = {
            "tree": tree,
            "views": list(tree.iter("node"))
        }
        self.window_dumps.append(new_dump)
        return new_dump

    def _remove_window_dump(self, dump):
        """Remove a views dump from the list.
        @param dump: window dump object.
        """
        self.window_dumps.remove(dump)

    def run(self):
        """Run UI automator"""
        self.temp_dumpfile = tempfile.mktemp()
        while self.do_run:
            self._dump_views()

            tree = ET.parse(self.temp_dumpfile).getroot()
            dump = self._add_window_dump(tree)
            r_node = random.choice(dump["views"])
            pkg_name = r_node.attrib["package"]

            if pkg_name == self.package:
                self._trigger_event(r_node)
                dump["views"].remove(r_node)
            elif "packageinstaller" in pkg_name:
                self._remove_window_dump(dump)
                for node in dump["views"]:
                    if "permission_allow_button" in node.attrib["resource-id"]:
                        self._trigger_event(node)
                        break

    def stop(self):
        """Stop UI automator"""
        self.do_run = False
        self.join()

        os.unlink(self.temp_dumpfile)

    def _trigger_event(self, node):
        """Trigger an event on a view.
        @param node: view node.
        """
        x, y = node.attrib["bounds"].split("][")[0][1:].split(",")
        _tap(x, y)

        if node.attrib["focusable"] == "true":
            _input_text(random_str())
