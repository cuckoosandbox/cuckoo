# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path

from lib.cuckoo.common.abstracts import Processing

class TLSMasterKeys(Processing):
    """Cross-references master keys extracted from the monitor and key
    information extracted from the PCAP to dump a master key file."""

    order = 2

    def run(self):
        metakeys, tlskeys = {}, {}

        # Fetch all meta information from the PCAP.
        if "network" in self.results and "tls" in self.results["network"]:
            for row in self.results["network"]["tls"]:
                if "client_random" in row and row["client_session_id"]:
                    random = row["client_random"]
                    session_id = row["client_session_id"]
                    metakeys[random] = session_id
                if "server_random" in row and row["server_session_id"]:
                    random = row["server_random"]
                    session_id = row["server_session_id"]
                    metakeys[random] = session_id

        # Fetch all key information from the behavior logs.
        if "behavior2" in self.results and \
                "processes" in self.results["behavior2"]:
            for process in self.results["behavior2"]["processes"]:
                if process["process_path"] != "lsass.exe":
                    continue

                # TODO This way of enumeration will be changed soon. Also, the
                # TLS key information should be more easily accessible.
                for thread in process["threads"]:
                    for call in thread["calls"]:
                        if call["api"] != "PRF":
                            continue

                        args = call["arguments"]
                        if not args["master_secret"]:
                            continue

                        client_random = args["client_random"].encode("latin-1")
                        server_random = args["server_random"].encode("latin-1")
                        master_secret = args["master_secret"].encode("latin-1")
                        tlskeys[client_random] = master_secret
                        tlskeys[server_random] = master_secret

        f = open(os.path.join(self.analysis_path, "tlsmaster.txt"), "wb")
        for random, secret in tlskeys.items():
            if random in metakeys:
                print>>f, "RSA Session-ID:%s Master-Key:%s" % (
                    metakeys[random].encode("hex"), secret.encode("hex"))
