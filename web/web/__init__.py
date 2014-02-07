# Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys
import os
from django.conf import settings

sys.path.append(settings.CUCKOO_PATH)

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.config import Config

cfg = Config(cfg=os.path.join(CUCKOO_ROOT, "conf", "reporting.conf")).mongodb

# Checks if mongo reporting is enabled in Cuckoo.
if not cfg.get("enabled"):
    raise Exception("Mongo reporting module is not enabled in cuckoo, aborting!")

# Get connection options from reporting.conf.
settings.MONGO_HOST = cfg.get("host", "127.0.0.1")
settings.MONGO_PORT = cfg.get("port", 27017)