# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mmap
import os
import re
import struct

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.whitelist import is_whitelisted_domain

HTTP_REGEX = (
    "(https?://)(["
    "[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]\\."
    "[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]\\."
    "[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]\\."
    "[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]"
    "]|[a-zA-Z0-9\\.-]+)"
    "(:\\d+)?(/[a-zA-Z0-9_:%?=/\\.-]+)"
)

class ProcessMemory(Processing):
    """Analyze process memory dumps."""
    def read_dump(self, filepath):
        f = open(filepath, "rb")

        while True:
            buf = f.read(24)
            if not buf:
                break

            row = struct.unpack("QIIII", buf)
            addr, size, state, typ, protect = row

            yield {
                "addr": "0x%x" % addr,
                "end": "0x%x" % (addr + size),
                "size": size,
                "type": typ,
                "protect": protect,
                "offset": f.tell(),
            }

            f.seek(size, 1)

    def extract_urls(self, filepath):
        # http://stackoverflow.com/a/454589
        urls = set()
        f = open(filepath, "rb")
        m = mmap.mmap(f.fileno(), 0, access=mmap.PROT_READ)

        for url in re.findall(HTTP_REGEX, m):
            if not is_whitelisted_domain(url[1]):
                urls.add("".join(url))

        return urls

    def run(self):
        """Run analysis.
        @return: structured results.
        """
        self.key = "procmemory"
        results = []

        if os.path.exists(self.pmemory_path):
            for dmp in os.listdir(self.pmemory_path):
                dump_path = os.path.join(self.pmemory_path, dmp)
                dump_file = File(dump_path)

                if "-" in os.path.basename(dump_path):
                    pid = int(os.path.basename(dump_path).split("-")[0])
                else:
                    pid = int(os.path.basename(dump_path).split(".")[0])

                proc = dict(
                    file=dump_path, pid=pid,
                    yara=dump_file.get_yara("memory"),
                    urls=list(self.extract_urls(dump_path)),
                    space=list(self.read_dump(dump_path)),
                )

                results.append(proc)

        return results
