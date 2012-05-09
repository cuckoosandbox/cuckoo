from lib.cuckoo.common.abstracts import Signature

class CreatesExe(Signature):
    name = "creates_exe"
    description = "Creates a Windows executable on the filesystem"
    severity = 2

    def run(self, results):
        for file_name in results["behavior"]["summary"]["files"]:
            if file_name.endswith(".exe"):
                self.data.append({"file_name" : file_name})
                return True

        return False
