# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import os.path
import socket
import tempfile
import threading

from lib.cuckoo.common.config import Config

cfg = Config()
log = logging.getLogger(__name__)
unixpath = tempfile.mktemp()
lock = threading.Lock()

vpns = {}

def rooter(command, *args, **kwargs):
    if not os.path.exists(cfg.cuckoo.rooter):
        log.critical("Unable to passthrough root command (%s) as the rooter "
                     "unix socket doesn't exist.", command)
        return

    lock.acquire()

    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    if os.path.exists(unixpath):
        os.remove(unixpath)

    s.bind(unixpath)

    try:
        s.connect(cfg.cuckoo.rooter)
    except socket.error as e:
        log.critical("Unable to passthrough root command as we're unable to "
                     "connect to the rooter unix socket: %s.", e)
        return

    s.send(json.dumps({
        "command": command,
        "args": args,
        "kwargs": kwargs,
    }))

    ret = json.loads(s.recv(0x10000))

    lock.release()

    if ret["exception"]:
        log.warning("Rooter returned error: %s", ret["exception"])

    return ret["output"]
