# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.

import json

class Config:
    def __init__(self, cfg):
        """@param cfg: configuration file."""
        config = json.load(open(cfg))
        for section in config:
            for name in config[section]:
                value = config[section][name]
                # Options can be UTF encoded.
                if isinstance(value, basestring):
                    try:
                        value = value.encode("utf-8")
                    except UnicodeEncodeError:
                        pass
                setattr(self, name, value)