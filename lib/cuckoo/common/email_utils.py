# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import email
import mimetypes
from email.header import decode_header, make_header

import utils

SAFE_MEDIA_TYPE = ['text/plain', 'text/html']
EMAIL_MAGIC = ['MIME-Version:', 'Received:', 'From:', 'Return-Path:', 'Delivered-To:']

def find_attachments_in_email(s, expand_attachment):
    """Extracts interesting attachments in MIME or RFC 2822-based email
    message.
    @param s: a string object.
    @param expand_attachment: expand attached rfc2822 messages.
    @return: list of (tempfile_path, filename, content_type) tuples"""
    atts = []

    s = s.lstrip(" \t\r\n") # Python's email parser cannot handle leading spaces
    mesg = email.message_from_string(s)
    _find_attachments_in_email(mesg, expand_attachment, atts)
    return atts

def _find_attachments_in_email(mesg, expand_attachment, atts):
    for part in mesg.walk():
        content_type = part.get_content_type()
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True)

        if content_type.startswith('text/') and expand_attachment:
            normalized = payload.lstrip(" \t\r\n")
            if any(normalized.startswith(m) for m in EMAIL_MAGIC):
                new_mesg = email.message_from_string(normalized)
                _find_attachments_in_email(new_mesg, expand_attachment, atts)
                continue

        if content_type in SAFE_MEDIA_TYPE:
            continue

        filename = part.get_filename()
        if filename is None:
            ext = mimetypes.guess_extension(content_type) or ''
            filename = '<unknown>' + ext
        else:
            # Sanitize the header value
            filename = _decode_header(filename)
            filename = utils.get_filename_from_path(filename)
        tempfile_path = utils.store_temp_file(payload, filename)
        atts.append((tempfile_path, filename, content_type))

def _decode_header(s):
    t = decode_header(s)
    return unicode(make_header(t))
