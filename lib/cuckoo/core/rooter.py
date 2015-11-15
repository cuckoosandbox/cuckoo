# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import os.path
import socket

from lib.cuckoo.common.config import Config

cfg = Config()
log = logging.getLogger(__name__)

def rooter(command, *args, **kwargs):
    if not os.path.exists(cfg.rooter):
        log.critical("Unable to passthrough root command as the rooter unix "
                     "socket doesn't exist.")
        return

    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    try:
        s.connect(cfg.rooter)
    except socket.error as e:
        log.critical("Unable to passthrough root command as we're unable to "
                     "connect to the rooter unix socket: %s.", e)
        return

    s.send(json.dumps({
        "command": command,
        "args": args,
        "kwargs": kwargs,
    }))

def vpn_enable(ipaddr, vpn):
    return rooter("vpn_enable", ipaddr=ipaddr, vpn=vpn)

def vpn_disable(ipaddr, vpn):
    return rooter("vpn_disable", ipaddr=ipaddr, vpn=vpn)
