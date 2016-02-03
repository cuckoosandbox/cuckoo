# Copyright (C) 2014-2016 Cuckoo Foundation.
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
                if name == "file_name":
                    value = config.get(section, name)
                else:
                    try:
                        value = config.getboolean(section, name)
                    except ValueError:
                        try:
                            value = config.getint(section, name)
                        except ValueError:
                            value = config.get(section, name)
                setattr(self, name, value)

    def get_options(self):
        """Get analysis options.
        @return: options dict.
        """
        # The analysis package can be provided with some options in the
        # following format:
        #   option1=value1,option2=value2,option3=value3
        #
        # Here we parse such options and provide a dictionary that will be made
        # accessible to the analysis package.
        options = {}
        if hasattr(self, "options") and len(self.options) > 0:
            try:
                # Split the options by comma.
                fields = self.options.split(",")
            except ValueError:
                pass
            else:
                for field in fields:
                    # Split the name and the value of the option.
                    try:
                        # Sometimes, we have a key without a value (i.e. it's a
                        # command line argument), so we can't use the
                        # `key, value = field.split("=", 1)` style here
                        parts = field.split("=", 1)
                    except ValueError:
                        pass
                    else:
                        key = parts[0].strip()
                        arg_prefix = "arg-"
                        if not key.startswith(arg_prefix):
                            # If the parsing went good, we add the option to the
                            # dictionary.
                            value = parts[1].strip()
                            options[key] = value
                        elif len(key) > len(arg_prefix):
                            # Remove "arg-" prefix from the key
                            key = key[4:]; parts[0] = key
                            # Add this key (with a value maybe) to the args
                            if "args" not in options: options["args"] = []
                            options["args"] += parts
        return options
