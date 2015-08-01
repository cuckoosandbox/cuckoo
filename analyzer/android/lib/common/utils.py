# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.results import NetlogFile

def send_file(name,data):
    """Send file to result server"""
    nf = NetlogFile(name)
    nf.sock.sendall(data)
    nf.close()