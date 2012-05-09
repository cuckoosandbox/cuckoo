from lib.cuckoo.common.utils import File
from lib.cuckoo.common.abstracts import Processing

class FileAnalysis(Processing):
    def run(self):
        self.key = "file"
        file_info = File(self.file_path).get_all()
        return file_info
