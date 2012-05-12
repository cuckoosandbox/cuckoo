import os
import time
import logging
import xmlrpclib
from StringIO import StringIO
from zipfile import ZipFile, BadZipfile, ZIP_DEFLATED

from lib.cuckoo.common.constants import CUCKOO_GUEST_PORT, CUCKOO_GUEST_INIT, CUCKOO_GUEST_COMPLETED, CUCKOO_GUEST_FAILED

log = logging.getLogger(__name__)

class GuestManager:
    def __init__(self, ip, platform="windows"):
        self.platform = platform
        self.server = xmlrpclib.Server("http://%s:%s" % (ip, CUCKOO_GUEST_PORT), allow_none=True)

    def wait(self, status):
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

    def start_analysis(self, options):
        if not os.path.exists(options["file_path"]):
            return False

        self.wait(CUCKOO_GUEST_INIT)
        self.upload_analyzer()
        self.server.add_config(options)

        file_data = open(options["file_path"], "rb").read()
        data = xmlrpclib.Binary(file_data)

        self.server.add_malware(data, options["file_name"])
        self.server.execute()

    def wait_for_completion(self):
        while True:
            try:
                status = self.server.get_status()
                if status == CUCKOO_GUEST_COMPLETED:
                    log.info("Analysis completed successfully")
                    break
                elif status == CUCKOO_GUEST_FAILED:
                    log.error("Analysis failed: %s" % self.server.get_error())
                    return False
            except:
                pass

            time.sleep(1)
        
        return True

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
