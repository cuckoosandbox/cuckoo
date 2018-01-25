# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import olefile
import oletools.oleobj

from cuckoo.common.abstracts import Extractor

class OleStream(Extractor):
    yara_rules = "OleStream"
    minimum = "2.0.5"

    def handle_yara(self, filepath, match):
        ole = olefile.olefile.OleFileIO(filepath)
        for stream in ole.listdir():
            if stream[-1] != "\x01Ole10Native":
                continue

            content = ole.openstream(stream).read()
            stream = oletools.oleobj.OleNativeStream(content)
            self.push_blob(stream.data, "binaries", None, {
                "filename": stream.filename.decode("latin-1"),
                "src_path": stream.src_path.decode("latin-1"),
                "temp_path": stream.temp_path.decode("latin-1"),
            })
