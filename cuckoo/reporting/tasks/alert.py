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

import smtplib

from cuckoo.reporting.observers import BaseObserver

class Report(BaseObserver):
    """
    Alert matched signatures.
    """

    def send_alert(self, file_info, signature):
        """
        Send email alert containing trigger information.
        @param file_info = dictionary containing metadata of the analyzed file
        @param signature = dictionary containing info on the triggered signature
        """
        message =  "From: %s\n" % self._options["from"]
        message += "To: %s\n" % ", ".join(self._options["to"].strip().split(","))
        message += ("Subject: [Cuckoo Alert] Signature \"%s\" triggered by %s\n"
                    % (signature["name"], file_info["md5"]))
        message += "\n"
        message += "This is an automated alert to notify you that one of the " \
                   "analysis performed by your Cuckoo Sandbox triggered a "    \
                   "signature.\n"
        message += "\n"
        message += "File name: %s\n" % file_info["name"]
        message += "File type: %s\n" % file_info["type"]
        message += "File MD5: %s\n" % file_info["md5"]
        message += "File SHA-1: %s\n" % file_info["sha1"]
        message += "\n"
        message += "Signature name: %s\n" % signature["name"]
        message += "Signature severity: %s\n" % signature["severity"]
        message += "Signature description: %s\n" % signature["description"]

        try:
            smtp = smtplib.SMTP(self._options["server"])
            
            if self._options["tls"]:
                smtp.starttls()

            smtp.login(self._options["username"], self._options["password"])
            smtp.sendmail(self._options["from"],
                          self._options["to"].strip().split(","),
                          message)
        except smtplib.SMTPException, why:
            return False

        return True

    def update(self, results):
        if len(results["signatures"]) > 0:
            for signature in results["signatures"]:
                self.send_alert(results["file"], signature)
