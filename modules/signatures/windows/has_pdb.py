# Copyright (C) 2010-2015 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class HasPdb(Signature):
    name = "has_pdb"
    description = "This executable has a PDB path"
    severity = 1

    def on_complete(self):
        pdb_path = self.get_results("static", {}).get("pdb_path")
        if pdb_path:
            self.mark_ioc("pdb_path", pdb_path)
            return True
