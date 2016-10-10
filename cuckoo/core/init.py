# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys

from cuckoo.misc import cwd

def write_supervisor_conf(username):
    """Writes supervisord.conf configuration file if it does not exist yet."""
    if os.path.exists(cwd("supervisord.conf")):
        return

    with open(cwd("supervisord.conf"), "wb") as f:
        # Temporarily redirect stdout to our file.
        f, sys.stdout = sys.stdout, f

        if os.environ.get("VIRTUAL_ENV"):
            virtualenv = os.path.join(os.environ["VIRTUAL_ENV"], "bin")
            python_path = os.path.join(virtualenv, "python")
            cuckoo_path = os.path.join(virtualenv, "cuckoo")
        else:
            python_path = "python"
            cuckoo_path = "cuckoo"

        print "[supervisord]"
        print "logfile =", cwd("supervisord", "log.log")
        print "pidfile =", cwd("supervisord", "pidfile")
        print "user =", username
        print
        print "[supervisorctl]"
        print "serverurl = unix://%s" % cwd("supervisord", "unix.sock")
        print
        print "[rpcinterface:supervisor]"
        print "supervisor.rpcinterface_factory =",
        print "supervisor.rpcinterface:make_main_rpcinterface"
        print
        print "[unix_http_server]"
        print "file =", cwd("supervisord", "unix.sock")
        print
        print "[program:cuckoo]"
        print "command = %s -d -m 10000" % cuckoo_path
        print "user =", username
        print "startsecs = 30"
        print "autorestart = true"
        print
        print "[program:cuckoo-process]"
        print "command = %s process p%%(process_num)d" % cuckoo_path
        print "process_name = cuckoo-process_%(process_num)d"
        print "numprocs = 4"
        print "user =", username
        print "autorestart = true"
        print
        print "[program:distributed]"
        print "command = %s -m cuckoo.distributed.worker" % python_path
        print "user =", username
        print "autostart = false"
        print "autorestart = true"
        print 'environment = CUCKOO_APP="worker",CUCKOO_CWD="%s"' % cwd()

        f, sys.stdout = sys.stdout, f
