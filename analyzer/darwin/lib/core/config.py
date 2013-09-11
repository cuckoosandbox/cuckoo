# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import ConfigParser

class Config:
    def __init__(self, cfg):
        """@param cfg: configuration file."""
        config = ConfigParser.ConfigParser(allow_no_value=True)
        config.read(cfg)

        for section in config.sections():
            for name, raw_value in config.items(section):
                try:
                    value = config.getboolean(section, name)
                except ValueError:
                    try:
                        value = config.getint(section, name)
                    except ValueError:
                        value = config.get(section, name)

                setattr(self, name, value)
