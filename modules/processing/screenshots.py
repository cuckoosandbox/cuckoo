import os
import base64

from lib.cuckoo.common.abstracts import Processing

class Screenshots(Processing):
    def run(self):
        self.key = "screenshots"
        shots = []

        if not os.path.exists(self.shots_path):
            return shots

        counter = 1
        for shot_name in os.listdir(self.shots_path):
            if not shot_name.endswith(".jpg"):
                continue

            shot_path = os.path.join(self.shots_path, shot_name)

            if os.path.getsize(shot_path) == 0:
                continue

            shot = {}
            shot["id"] = counter
            shot["data"] = base64.b64encode(open(shot_path, "rb").read())
            shots.append(shot)

            counter += 1

        shots.sort(key=lambda shot: shot["id"])

        return shots
