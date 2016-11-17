# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import ConfigParser
import os

from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.common.objects import Dictionary
from cuckoo.misc import cwd

class Config:
    """Configuration file parser."""

    def __init__(self, file_name="cuckoo", cfg=None):
        """
        @param file_name: file name without extension.
        @param cfg: configuration file path.
        """
        env = {}
        self.file_name = file_name
        for key, value in os.environ.items():
            if key.startswith("CUCKOO_"):
                env[key] = value

        config = ConfigParser.ConfigParser(env)

        if cfg:
            config.read(cfg)
        else:
            config.read(cwd("conf", "%s.conf" % file_name))

        for section in config.sections():
            setattr(self, section, Dictionary())
            for name, raw_value in config.items(section):
                try:
                    # Ugly fix to avoid '0' and '1' to be parsed as a
                    # boolean value.
                    # We raise an exception to goto fail^w parse it
                    # as integer.
                    if config.get(section, name) in ["0", "1"]:
                        raise ValueError

                    value = config.getboolean(section, name)
                except ValueError:
                    try:
                        value = config.getint(section, name)
                    except ValueError:
                        value = config.get(section, name)

                setattr(getattr(self, section), name, value)

    def get(self, section):
        """Get option.
        @param section: section to fetch.
        @raise CuckooOperationalError: if section not found.
        @return: option value.
        """
        try:
            return getattr(self, section)
        except AttributeError as e:
            raise CuckooOperationalError("Option %s is not found in "
                                         "configuration, error: %s" %
                                         (section, e))

    def to_dict(self, privacy=True):
        from glob import glob

        data = {}
        blacklist_defs = ["password", "pwd", "credentials", "api_key", "apikey", "pass"]
        blacklist = {
            "cuckoo": {
                "database": ["connection"]
            },
            "processing": {
                "virustotal": ["key"],
                "googleplay": ["google_password"]
            },
        }


        # read config, fetch sections
        cfg = {z: getattr(self, z) for z in dir(self) if isinstance(getattr(self, z), dict)}

        # iterate sections and their values
        for section, values in cfg.iteritems():
            for k, v in values.iteritems():
                if privacy:  # block blacklisted entries
                    if k in ["cuckoo_cwd", "cuckoo_app"]:
                        continue
                    elif k in blacklist_defs:
                        v = "[removed]"
                    elif cfg_name in blacklist:
                        if section in blacklist[cfg_name] and \
                                        k in blacklist[cfg_name][section]:
                            v = "[removed]"

                if cfg_name not in data:
                    data[cfg_name] = {}
                if section not in data[cfg_name]:
                    data[cfg_name][section] = {}
                if k not in data[cfg_name][section]:
                    data[cfg_name][section][k] = {}

                # build return dict
                data[cfg_name][section][k] = v

        return data

def parse_options(options):
    """Parse the analysis options field to a dictionary."""
    ret = {}
    for field in options.split(","):
        if "=" not in field:
            continue

        key, value = field.split("=", 1)
        ret[key.strip()] = value.strip()
    return ret

def emit_options(options):
    """Emit the analysis options from a dictionary to a string."""
    return ",".join("%s=%s" % (k, v) for k, v in options.items())
