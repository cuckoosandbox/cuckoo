import os

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.utils import File

class Dropped(Processing):
    def run(self):
        self.key = "dropped"
        dropped_files = []

        if not os.path.exists(self.dropped_path):
            return dropped_files

        for file_name in os.listdir(self.dropped_path):
            file_path = os.path.join(self.dropped_path, file_name)
            file_info = File(file_path).get_all()
            dropped_files.append(file_info)

        return dropped_files
