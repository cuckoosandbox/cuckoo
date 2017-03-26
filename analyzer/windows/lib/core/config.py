# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import ConfigParser

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

    def parse_options(self, options):
        """Get analysis options.
        @return: options dict.
        """
        # The analysis package can be provided with some options in the
        # following format:
        #   option1=value1,option2=value2,option3=value3
        # or in the JSON format
        try:
            return json.loads(options)
        except ValueError:
            ret = {}
            for field in options.split(","):
                if "=" not in field:
                    continue

                key, value = field.split("=", 1)
                ret[key.strip()] = value.strip()
            return ret
