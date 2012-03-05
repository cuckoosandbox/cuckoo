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
import json
import smtplib

from cuckoo.reporting.observers import BaseObserver

SERVER = ""
USERNAME = ""
PASSWORD = ""
FROM = ""
TO = []

class Report(BaseObserver):
    """
    Alert matched signatures.
    """

    def send_alert(self, signature):
        message = "Signature matched: %s" % signature["name"]

        try:
            smtp = smtplib.SMTP(SERVER)
            smtp.starttls()
            smtp.login(USERNAME, PASSWORD)
            smtp.sendmail(FROM, TO, message)
        except smtplib.SMTPException, why:
            print why

    def update(self, results):
        if len(results["signatures"]) > 0:
            for signature in results["signatures"]:
                self.send_alert(signature)

