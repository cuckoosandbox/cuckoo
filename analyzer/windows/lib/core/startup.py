import os
import logging

from lib.core.paths import PATHS

log = logging.getLogger()

def create_folders():
    for name, folder in PATHS.items():
        if os.path.exists(folder):
            continue

        try:
            os.makedirs(folder)
        except OSError as e:
            pass

def init_logging():
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    sh = logging.StreamHandler()
    sh.setFormatter(formatter)
    log.addHandler(sh)
    fh = logging.FileHandler(os.path.join(PATHS["root"], "analysis.log"))
    fh.setFormatter(formatter)
    log.addHandler(fh)
    log.setLevel(logging.DEBUG)
