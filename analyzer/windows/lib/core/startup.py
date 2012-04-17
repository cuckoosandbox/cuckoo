import os

from lib.core.paths import PATHS

def create_folders():
    for name, folder in PATHS.items():
        if os.path.exists(folder):
            continue

        try:
            os.makedirs(folder)
        except OSError as e:
            pass
