# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import zipfile

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError

class Zipdropfiles(Processing):
    """Zip Dropped files."""

    def run(self):
        """Run analysis.
        @return: zip up dropped files.
        """
        self.key = "zipdropfiles"
        dropped_files = []
        
        zip_file = self.analysis_path + "/files.zip"
        dir = self.dropped_path
        
        zip = zipfile.ZipFile(zip_file, 'w', compression=zipfile.ZIP_DEFLATED)
        root_len = len(os.path.abspath(dir))
        for root, dirs, files in os.walk(dir):
            archive_root = os.path.abspath(root)[root_len:]
            for f in files:
                fullpath = os.path.join(root, f)
                archive_name = os.path.join(archive_root, f)
                print f
                zip.write(fullpath, archive_name, zipfile.ZIP_DEFLATED)
        zip.close()
        return zip_file
