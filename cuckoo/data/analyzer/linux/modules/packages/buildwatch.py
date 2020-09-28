import logging
import os

from zipfile import ZipFile

from lib.common.abstracts import Package
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

    def start(self, path):
        self.unzip(path)
        instructions = os.path.join(os.getcwd(), ".buildwatch.sh")
        os.chmod(instructions, 0o755)
        return self.execute(["sh", "-c", instructions])
