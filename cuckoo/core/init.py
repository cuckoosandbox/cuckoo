# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import jinja2
import os

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
