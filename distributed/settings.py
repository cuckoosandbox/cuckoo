# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

# Database connection URI. PostgreSQL or MySQL suggested.
# Examples, see documentation for more:
# postgresql://foo:bar@localhost:5432/mydatabase
# mysql://foo:bar@localhost/mydatabase
SQLALCHEMY_DATABASE_URI = "postgresql://cuckoo:cuckoo@localhost/distributed"

# Secret key used by Flask to generate sessions etc. (This feature is not
# actually used at the moment as we have no user accounts etc).
SECRET_KEY = os.urandom(32)

# A list of reporting formats, e.g., json.
report_formats = "json",

# Fetch the pcap?
pcap = False

# Directory for storing samples as long as their task is available.
samples_directory = "/tmp"

# Directory for storing reports as long as their task is available.
reports_directory = "/tmp"

# Rough interval between each status checkup per Cuckoo node. As it's not
# necessary to check the status every second half a minute should do.
interval = 10

# Threshold and amount of tasks to push every time a Cuckoo node requires
# more samples. That is, whenever the "pending" task count drops below
# "threshold" tasks, "threshold" tasks are submitted to the node.
threshold = 500
