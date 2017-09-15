# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import subprocess

from lib.common.abstracts import Auxiliary

log = logging.getLogger(__name__)

NXLOG_CONF = 'C:/Program Files (x86)/nxlog/conf/nxlog.conf'
HOSTNAME_DUMMY_VAR = 'CUCKOOBOX'

class TagHost(Auxiliary):
    """
    A module for rewriting a guests hostname so event logs from a specific
    analysis run can be easily identified in event logs.
    """
    def __init__(self, options={}, analyzer=None):
        Auxiliary.__init__(self, options, analyzer)

    def rewrite_hostname(self):
        if 'host_tag' not in self.options:
            log.info("No tag provided. Leaving guest hostname alone.")
            return

        # Make sure an NXLog configuration exists
        if not os.path.exists(NXLOG_CONF):
            log.error("Couldn't find an NXLog configuration.")
            return

        try:
            # Get our tag from the supplied "host_tag" option
            tag = self.options['host_tag']
            log.info("Rewriting guest hostname to: %s", tag)

            # Rewrite the dummy variable with the supplied tag
            lines = []
            with open(NXLOG_CONF) as infile:
                for line in infile:
                    line = line.replace(HOSTNAME_DUMMY_VAR, tag)
                    lines.append(line)
            with open(NXLOG_CONF, 'w') as outfile:
                for line in lines:
                    outfile.write(line)
        except Exception as e:
            log.error("Error rewriting the NXLog config: %s", e)
            return

        try:
            # Restart the NXLog service after rewriting the config
            log.info("Restarting NXLog for good measure.")
            subprocess.call('net stop nxlog && net start nxlog', shell=True)
        except Exception as e:
            log.error("Error restarting NXLog to apply config: %s", e)
            return

    def start(self):
        self.rewrite_hostname()
        return True

    def stop(self):
        # Stop NXLog at the end of the run so we don't 
        # leave any stale connections open
        try:
            log.info("Stopping NXLog on guest.")
            subprocess.call('net stop nxlog', shell=True)
        except:
            log.error("Error attempting to stop NXLog on the guest.")
        return True
