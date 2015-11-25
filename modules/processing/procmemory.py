# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import re

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.constants import CUCKOO_ROOT
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

    def run(self):
        """Run analysis.
        @return: structured results.
        """
        self.key = "procmemory"
        results = []

        if os.path.exists(self.pmemory_path):
            for dmp in os.listdir(self.pmemory_path):
                dmp_path = os.path.join(self.pmemory_path, dmp)
                dmp_file = File(dmp_path)

                # Let's hope the file is not too big.
                buf = open(dmp_path, "rb").read()
                urls = set()
                for url in re.findall(HTTP_REGEX, buf):
                    if not is_whitelisted_domain(url[1]):
                        urls.add("".join(url))

                proc = dict(
                    file=dmp_path,
                    pid=int(os.path.basename(dmp_path).split("-")[0]),
                    yara=dmp_file.get_yara(os.path.join(CUCKOO_ROOT, "data", "yara", "index_memory.yar")),
                    urls=list(urls),
                )

                results.append(proc)

        return results
