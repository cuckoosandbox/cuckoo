# Cuckoo Sandbox - Automated Malware Analysis
# Copyright (C) 2010-2012  Claudio "nex" Guarnieri (nex@cuckoobox.org)
# http://www.cuckoobox.org
#
# This file is part of Cuckoo.
#
# Cuckoo is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Cuckoo is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/.

import os
import base64

from cuckoo.processing.observers import Analysis

class Screenshots(Analysis):
    def process(self):
        self.key = "screenshots"
        shots = []

        counter = 1
        for shot_name in os.listdir(self._shots_path):
            shot_path = os.path.join(self._shots_path, shot_name)

            if os.path.getsize(shot_path) == 0:
                continue

            shot = {}
            shot["id"] = counter
            shot["data"] = base64.b64encode(open(shot_path, "rb").read())
            shots.append(shot)

            counter += 1

        shots.sort(key=lambda shot: shot["id"])

        return shots
