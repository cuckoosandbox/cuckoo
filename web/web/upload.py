# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from tempfile import mkdtemp
from django.conf import settings
from django.core.files.uploadedfile import TemporaryUploadedFile
from django.core.files.uploadhandler import TemporaryFileUploadHandler

class CuckooTemporaryUploadedFile(TemporaryUploadedFile):
    """Custom uploader to preserve file names.
    It creates a tmp directory with a random name and inside the original file is placed.
    """

    def __init__(self, name, content_type, size, charset):
        path = settings.CUCKOO_FILE_UPLOAD_TEMP_DIR[0]
        if path:
            # Create temp directory if not exists.
            if not os.path.exists(path):
                os.mkdir(path)

            # Temp file handler.
            file = os.path.join(mkdtemp(dir=path), name)
            super(TemporaryUploadedFile, self).__init__(open(file, "wb"), name, content_type, size, charset)
        else:
            raise Exception("Missing CUCKOO_FILE_UPLOAD_TEMP_DIR in settings.py")

class CuckooTemporaryFileUploadHandler(TemporaryFileUploadHandler):
    """Custom uploder to use CuckooTemporaryUploadedFile."""

    def new_file(self, file_name, *args, **kwargs):
        super(CuckooTemporaryFileUploadHandler, self).new_file(file_name, *args, **kwargs)
        self.file = CuckooTemporaryUploadedFile(self.file_name, self.content_type, 0, self.charset)