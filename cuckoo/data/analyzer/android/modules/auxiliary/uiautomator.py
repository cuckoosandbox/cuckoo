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

def tap(x, y):
    """Generate a tap event."""
    try:
        args = [
            "/system/bin/sh",
            "/system/bin/input", "tap", x, y
        ]
        p = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        _, err = p.communicate()
        if p.returncode:
            raise OSError(err)
    except OSError as e:
        log.error("Failed to generate touch event: %s", e)

def input_rtext():
    """Input text event."""
    try:
        args = [
            "/system/bin/sh", 
            "/system/bin/input", "text", random_str()
        ]
        p = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        _, err = p.communicate()
        if p.returncode:
            raise OSError(err)
    except OSError as e:
        log.error("Failed to generate text event: %s", e)

def dump_views(filepath):
    """Dump the views in the current window with uiautomator.
    @param filepath: dump file path.
    @return: tree presentation of XML.
    """
    try:
        args = [
            "/system/bin/sh", 
            "/system/bin/uiautomator", "dump", filepath
        ]
        p = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        _, err = p.communicate()
        if p.returncode:
            raise OSError(err)
    except OSError as e:
        log.error("Failed to dump window's views: %s", e)

    return ET.parse(filepath).getroot()

class UIAutomator(threading.Thread, Auxiliary):
    """Generates random UI events."""

    def __init__(self, options={}):
        Auxiliary.__init__(self, options)
        threading.Thread.__init__(self)

        self.package = options.get("apk_entry", ":").split(":")[0]
        self.do_run = True
        self.window_dumps = []

    def _add_dump(self, tree):
        """Add a new views dump to the list.
        @param tree: layout tree node.
        """
        for d in self.window_dumps:
            if etree_compare(d, tree):
                return d

        self.window_dumps.append(tree)
        return tree

    def run(self):
        """Run UI automator"""
        tmp = tempfile.mktemp()
        root = dump_views(tmp)

        while self.do_run:
            rnode = random.choice(list(root.iter("node")))
            if rnode.attrib["package"] == self.package:
                self._trigger_event(rnode)

                root = self._add_dump(dump_views(tmp))

        os.unlink(tmp)

    def stop(self):
        """Stop UI automator"""
        self.do_run = False
        self.join()

    def _trigger_event(self, node):
        """Trigger an event on a view.
        @param node: view node.
        """
        x, y = node.attrib["bounds"].split("][")[0][1:].split(",")

        if node.attrib["focusable"] == "true":
            tap(x, y)
            input_rtext()
        else:
            tap(x, y)
