# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import json

from cuckoo.common.abstracts import Processing
from cuckoo.common.exceptions import CuckooProcessingError

log = logging.getLogger(__name__)

__author__  = "haam3r"
__version__ = "1.0.0"
__date__    = "2018-09-05"

try:
    import xmltodict
except ImportError:
    raise CuckooProcessingError('Unable to import required xmltodict module')

class Sysmon(Processing):
    """Parse exported Sysmon XML file to a json file"""

    def run(self):
        self.key = "sysmon"

        try:
            with open('%s/sysmon/sysmon.xml' % self.analysis_path) as xmlfile:
                data = xmltodict.parse(xmlfile)
        except Exception as e:
            raise CuckooProcessingError("Failed opening sysmon log: %s" & e.message)

        clean = {}
        for event in data['root']['Event']:
            clean[event['System']['EventRecordID']] = {}
            clean[event['System']['EventRecordID']]['System'] = {}
            clean[event['System']['EventRecordID']]['EventData'] = {}
            for k, v in event['System'].items():
                clean[event['System']['EventRecordID']]['System'][k] = v
            for eventdata in event['EventData']['Data']:
                clean[event['System']['EventRecordID']]['EventData'][eventdata['@Name']] = eventdata.get('#text', None)

        with open('%s/sysmon/sysmon.json' % self.analysis_path, 'w') as dump_file:
            json.dump(clean, dump_file)

        return clean

