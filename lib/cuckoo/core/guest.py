import os
import time
import xmlrpclib
from StringIO import StringIO
from zipfile import ZipFile, BadZipfile, ZIP_DEFLATED

from lib.cuckoo.common.constants import CUCKOO_GUEST_INIT, CUCKOO_GUEST_COMPLETED

class GuestManager:
    def __init__(self, ip, platform="windows"):
        self.platform = platform
        self.ip = ip
        self.port = 8000
        self.server = xmlrpclib.Server("http://%s:%s" % (self.ip, self.port))

    def wait(self, status=CUCKOO_GUEST_COMPLETED):
        while True:
            try:
                if self.server.get_status() == status:
                    break
            except:
                pass

            time.sleep(1)

        return True

    def upload_analyzer(self):
        zip_data = StringIO()
        zip_file = ZipFile(zip_data, "w", ZIP_DEFLATED)

        root = os.path.join("analyzer", self.platform)
        root_len = len(os.path.abspath(root))

        if not os.path.exists(root):
            return False

        for root, dirs, files in os.walk(root):
            archive_root = os.path.abspath(root)[root_len:]
            for name in files:
                path = os.path.join(root, name)
                archive_name = os.path.join(archive_root, name)
                zip_file.write(path, archive_name, ZIP_DEFLATED)

        zip_file.close()
        data = xmlrpclib.Binary(zip_data.getvalue())
        zip_data.close()

        self.server.add_analyzer(data)

    def start_analysis(self, task):
        if not os.path.exists(task.file_path):
            return False

        self.wait(CUCKOO_GUEST_INIT)
        self.upload_analyzer()
        self.server.add_config({"package" : task.package,
                                "file_name" : task.file_name})

        file_data = open(task.file_path, "rb").read()
        data = xmlrpclib.Binary(file_data)

        self.server.add_malware(data, task.file_name)
        self.server.execute()

    def save_results(self, folder):
        data = self.server.get_results()

        zip_data = StringIO()
        zip_data.write(data)

        with ZipFile(zip_data, "r") as archive:
            if not os.path.exists(folder):
                try:
                    os.mkdir(folder)
                except OSError:
                    return False

            archive.extractall(folder)

        return True
