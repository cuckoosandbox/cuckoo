import logging
import os
from zipfile import ZipFile

from lib.common.abstracts import Package
from lib.common.results import NetlogFile
from lib.common.exceptions import CuckooPackageError

log = logging.getLogger(__name__)


class Buildwatch(Package):
    """
    analysis package for buildwatch
    unzip repo execute costum commands
    """
    def __init__(self, *args, **kwargs):
        Package.__init__(self, *args, **kwargs)
        self.seen_pids = set()

    def unzip(self, path):
        with ZipFile(path, "r") as archive:
            try:
                archive.extractall(path=".")
            except BaseException as exc:
                raise CuckooPackageError(
                    "Something went wrong with the zipfile: {}".format(exc))

    def pre_recorded(self, path):
        log.info("Unzipping target")
        self.unzip(path)
        instructions = os.path.join(os.getcwd(), ".prebuild.sh")
        if os.path.isfile(instructions):
            log.info("Found prebuild.sh and executing it")
            os.chmod(instructions, 0o755)
            os.system(instructions)

    def start(self, path):
        instructions = os.path.join(os.getcwd(), ".buildwatch.sh")
        os.chmod(instructions, 0o755)
        log.info("Starting .buildwatch.sh in %s", os.getcwd())
        log.info("Executing: %s", " ".join(["sh", "-c", instructions]))
        return self.execute(["sh", "-c", instructions])

    @staticmethod
    def _upload_file(local, remote):
        if os.path.exists(local):
            nf = NetlogFile(remote)
            with open(local, "rb") as f:
                for chunk in f:
                    nf.sock.sendall(chunk)  # dirty direct send, no reconnecting
            nf.close()
        else:
            log.info("No program.log found")

    def finish(self):
        log.info("trying to upload program output currently in %s", os.getcwd())
        self._upload_file("program.log", "logs/program.log")