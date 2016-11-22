# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import jinja2
import os

from cuckoo.common.config import Config
from cuckoo.misc import cwd

def write_supervisor_conf(username):
    """Writes supervisord.conf configuration file if it does not exist yet."""
    # TODO Handle updates?
    if os.path.exists(cwd("supervisord.conf")):
        return

    if os.environ.get("VIRTUAL_ENV"):
        virtualenv = os.path.join(os.environ["VIRTUAL_ENV"], "bin")
        python_path = os.path.join(virtualenv, "python")
        cuckoo_path = os.path.join(virtualenv, "cuckoo")
    else:
        python_path = "python"
        cuckoo_path = "cuckoo"

    template = jinja2.Environment().from_string(
        open(cwd("cwd", "supervisord.jinja2", private=True), "rb").read()
    )

    with open(cwd("supervisord.conf"), "wb") as f:
        f.write(template.render({
            "cwd": cwd,
            "username": username,
            "cuckoo_path": cuckoo_path,
            "python_path": python_path,
        }).rstrip() + "\n")

def write_cuckoo_conf(cfg=None):
    if cfg is None:
        cfg = {}

    # Merge any provided configuration with the defaults and emit their values.
    raw = {}
    for filename, sections in Config.configuration.items():
        cfg[filename] = cfg.get(filename, {})
        raw[filename] = {}
        for section, entries in sections.items():
            # Process each entry.
            if not isinstance(entries, (tuple, list)):
                entries = entries,

            for entry in entries:
                real_section = entry.get("__section__", section)
                cfg[filename][real_section] = cfg[filename].get(section, {})
                raw[filename][real_section] = {}
                for key, value in entry.items():
                    if key == "__section__":
                        continue

                    raw_value = cfg[filename][real_section].get(key, value.default)
                    cfg[filename][real_section][key] = raw_value
                    raw[filename][real_section][key] = value.emit(raw_value)

    def _config(s):
        filename, section, key = s.split(":")
        return cfg[filename][section][key]

    raw["config"] = _config
    for filename in os.listdir(cwd("cwd", "conf", private=True)):
        template = jinja2.Environment().from_string(
            open(cwd("cwd", "conf", filename, private=True), "rb").read()
        )
        open(cwd("conf", filename), "wb").write(
            template.render(raw).rstrip() + "\n"
        )
