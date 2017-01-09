#!/usr/bin/env python
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import email
import imaplib
import hashlib
import tempfile
import smtplib
from time import sleep
import mimetypes
from email import Encoders
from email.mime.text import MIMEText
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase

try:
    from sflock.main import unpack
    from sflock.unpack import ZipFile
    from sflock.abstracts import File
except ImportError:
    print "Missed deps"\
    "sudo apt-get install p7zip-full rar unace-nonfree"\
    "sudo pip install -U sflock"

# Cuckoo root
CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CUCKOO_ROOT)
from lib.cuckoo.common.config import Config


from lib.cuckoo.core.database import Database
from lib.cuckoo.common.utils import store_temp_file

from sqlalchemy.sql import func
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Boolean, DateTime

main_db = Database()
Base = declarative_base()
email_config = Config("cuckoomx")

class CUCKOOMX(Base):
    __tablename__ = 'cuckoomx'
    id = Column(Integer, primary_key=True)
    sha256 = Column(String(64), nullable=False)
    email = Column(String(250), nullable=False)
    cuckoo_id = Column(Integer, nullable=False)
    reported = Column(Boolean, default=False)
    uploaded_date = Column(DateTime, default=func.now())

engine = create_engine(email_config.cuckoomx.get("db", "sqlite://cuckoomx.db"))
Base.metadata.create_all(engine)

def send_notification(db, db_entry = False):
    tasks = list()
    if db_entry:
        tasks = [db_entry]
    else:
        tasks = cuckoomx_db.query(CUCKOOMX).filter_by(reported=False).order_by(CUCKOOMX.id.asc())
    if tasks:
        for task in tasks:
            task_info = main_db.view_task(task.cuckoo_id)
            if task_info.status == "reported":
                send_email(email_config.cuckoomx.get("cuckoo_url"), str(task.cuckoo_id), task.email)
                task.reported = True
    db.commit()
def send_email(url, id, to):
    try:
        msg = MIMEMultipart()
        msg['Subject'] = "[Cuckoo] Analysis finished for: {}".format(id)
        msg['From'] = email_config.cuckoomx.get("user")
        msg['To'] = to
        msg['Body'] = url+id
        part = MIMEBase('application', "octet-stream")
        msgAlternative = MIMEMultipart('alternative')
        msg.attach(msgAlternative)
        msgAlternative.attach(MIMEText(url+id, 'plain'))

        server = smtplib.SMTP_SSL(email_config.cuckoomx.get("server"), int(email_config.cuckoomx.get("port")))
        server.login(email_config.cuckoomx.get("user"), email_config.cuckoomx.get("password"))
        #server.set_debuglevel(1)
        server.sendmail(email_config.cuckoomx.get("from"), re.findall(r'[\w.-]+@[\w.-]+', to), msg.as_string())
        server.quit()
    except Exception as e:
        print e

def get_new_emails(db):
    imaplib.IMAP4.debug = imaplib.IMAP4_SSL.debug = 1

    conn = imaplib.IMAP4_SSL(email_config.cuckoomx.get("server"))
    conn.login(email_config.cuckoomx.get("user"), email_config.cuckoomx.get("password"))
    conn.select("Inbox")

    (retcode, messages) = conn.search(None, "(UNSEEN)")
    if retcode == "OK" and messages:
        for num in messages[0].split(" "):
            if num:
                typ, data = conn.fetch(num,"(RFC822)")
                msg = email.message_from_string(data[0][1])
                if msg:
                    email_dict = dict()
                    email_dict["Attachments"] = list()
                    for k, v in msg.items():
                       email_dict[k] = v

                    if email_dict.get("Subject", ""):
                        print "[+] Procesing email with Subject: {0}".format(email_dict["Subject"])
                    for part in msg.walk():
                        attachment = False
                        if part.get_filename():
                            filename = part.get_filename()
                            content_type = part.get_content_type()
                            attachment = part.get_payload(decode=True)
                            
                            if attachment:
                                sha256 = hashlib.sha256(attachment).hexdigest()
                                #unpack it
                                z = ZipFile(File(contents=attachment, password=email_config.cuckoomx.get("archive_password")))
                                files = list(z.unpack(password=email_config.cuckoomx.get("archive_password"), duplicates=[]))
                                for file in files:
                                    new_file = db.query(CUCKOOMX).filter(CUCKOOMX.sha256 == file.sha256).first()
                                    if new_file is None:
                                        new_file = CUCKOOMX(sha256=file.sha256)

                                        temp_file_path = store_temp_file(file.contents, file.filename)
                                        task_id = main_db.add_path(
                                            file_path=temp_file_path
                                        )
                                        new_file.cuckoo_id = task_id
                                        new_file.email = email_dict.get("From", "")
                                        db.add(new_file)
                                        db.commit()
                                    else:
                                        send_notification(db, new_file)
                #mark as seen
                typ, data = conn.store(num,"+FLAGS","\Seen")

    conn.close()
    conn.logout()

if __name__ == "__main__":
    Base.metadata.bind = engine
    DBSession = sessionmaker(bind=engine)
    cuckoomx_db = DBSession()
    while True:
        try:
            send_notification(cuckoomx_db)
        except Exception as e:
            print e
        try:
            get_new_emails(cuckoomx_db)
        except Exception as e:
            print e
        sleep(30)
    cuckoomx_db.close()
