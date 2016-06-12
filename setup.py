#!/usr/bin/env python
# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - https://cuckoosandbox.org/.
# See the file 'docs/LICENSE.txt' for copying permission.

from setuptools import setup

setup(
    name="Cuckoo",
    version="2.0",
    author="Jurriaan Bremer",
    author_email="jbr@cuckoo.sh",
    packages=[
        "cuckoo",
    ],
    url="https://cuckoosandbox.org/",
    license="GPLv3",
    description="Automated Malware Analysis System",
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "cuckoo = cuckoo.main:main",
        ],
    },
    install_requires=[
        "alembic==0.8.0",
        "beautifulsoup4==4.4.1",
        "chardet==2.3.0",
        "click==6.6",
        "Django==1.8.4",
        "dpkt==1.8.7",
        "Flask==0.10.1",
        "HTTPReplay==0.1.15",
        "jsbeautifier==1.5.10",
        "lxml==3.6.0",
        "oletools==0.42",
        "pefile==2016.3.28",
        "pymisp==2.4.36",
        "pymongo==3.0.3",
        "python-dateutil==2.4.2",
        "python-magic==0.4.6",
        "requests[security]==2.7.0",
        "scapy==2.3.2",
        "SQLAlchemy==1.0.8",
        "wakeonlan==0.2.2",
    ],
)
