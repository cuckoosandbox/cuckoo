#!/usr/bin/env python
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import asyncore
import argparse
import os

from datetime import datetime
from smtpd import SMTPServer

class SmtpSink(SMTPServer):
    """SMTP Sinkhole server."""

    # Where mails should be saved.
    mail_dir = None

    def process_message(self, peer, mailfrom, rcpttos, data):
        """Custom mail processing used to save mails to disk."""
        # Save message to disk only if path is passed.
        if self.mail_dir:
            file_name = "%s" % datetime.now().strftime("%Y%m%d%H%M%S")

            # Duplicate check.
            i = 0
            while os.path.exists(os.path.join(self.mail_dir, file_name + str(i))):
                i += 1

            file_name = file_name + str(i)
            with open(os.path.join(self.mail_dir, file_name), "w") as mail:
                mail.write(data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="smtp_sinkhole.py",
                                     usage="%(prog)s [host [port]]",
                                     description="SMTP Sinkhole")
    parser.add_argument("host", nargs="?", default="127.0.0.1")
    parser.add_argument("port", nargs="?", type=int, default=1025)
    parser.add_argument("--dir", default=None,
                        help="Directory used to dump emails.")

    args = parser.parse_args()

    s = SmtpSink((args.host, args.port), None)
    s.mail_dir = args.dir

    try:
        asyncore.loop()
    except KeyboardInterrupt:
        pass
