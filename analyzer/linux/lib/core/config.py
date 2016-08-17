# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

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


    def get(self, name, default=None):
        if hasattr(self, name):
            return getattr(self, name)
        return default

    def get_options(self):
        """Get analysis options.
        @return: options dict.
        """
        # The analysis package can be provided with some options in the
        # following format:
        #   option1=value1,option2=value2,option3=value3
        # or in the JSON format
        #
        # Here we parse such options and provide a dictionary that will be made
        # accessible to the analysis package.
        options = {}
        if hasattr(self, "options"):
            if type(self.options) == dict:
                return self.options
            else:
                try:
                    # Split the options by comma.
                    fields = self.options.split(",")
                except ValueError as e:
                    pass
                else:
                    for field in fields:
                        # Split the name and the value of the option.
                        try:
                            key, value = field.split("=", 1)
                        except ValueError:
                            pass
                        else:
                            # If the parsing went good, we add the option to the
                            # dictionary.
                            options[key.strip()] = value.strip()

        return options
