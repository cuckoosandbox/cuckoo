import os
import sys
import ConfigParser

class Config:
    def __init__(self, root="."):
        config_path = os.path.join(root, "conf/cuckoo.conf")
        if not os.path.exists(config_path):
            sys.exit("Configuration file does not exist")

        config = ConfigParser.ConfigParser()
        config.read(config_path)

        self.debug = config.getboolean("Cuckoo", "debug")
        self.analysis_timeout = config.getint("Cuckoo", "analysis_timeout")
        self.critical_timeout = config.getint("Cuckoo", "critical_timeout")
        self.delete_original = config.getboolean("Cuckoo", "delete_original")
        self.machiner = config.get("Cuckoo", "machiner")
