# Copyright (C) 2017 Jesse Netz

import calendar
import datetime
import json
import logging
import os

from cuckoo.common.abstracts import Report
from cuckoo.common.exceptions import CuckooReportError

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxltieclient import TieClient
from dxltieclient.constants import HashType, TrustLevel, FileProvider


# Config file name and location
CONFIG_FILE_NAME = "dxlclient.config"
CONFIG_FILE = "/etc/opendxl/" + CONFIG_FILE_NAME
# Create DXL configuration from file
config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

def default(obj):
    if isinstance(obj, datetime.datetime):
        if obj.utcoffset() is not None:
            obj = obj - obj.utcoffset()
        return calendar.timegm(obj.timetuple()) + obj.microsecond / 1000000.0
    raise TypeError("%r is not JSON serializable" % obj)

class tieUpdate(Report):
    """Update McAfee TIE server with malicious rating."""

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        try:
            currentMD5 = results["target"]["file"]["md5"]
            currentSHA1 = results["target"]["file"]["sha1"]
            currentSHA256 = results["target"]["file"]["sha256"]
            currentFilename = results["target"]["file"]["name"]
            currentTrustLevel = results["info"]["score"]

            print currentMD5
            print currentSHA1
            print currentSHA256
            print currentFilename
            print currentTrustLevel

            if float(currentTrustLevel) < 4.0:
                print "Trust Level is " + str(currentTrustLevel) + ". No update required."
                return


            print "Opening DXL connection"
            with DxlClient(config) as client:

                #Connect to DXL fabric
                print "Connecting to DXL fabric."
                client.connect()

                #Create TIE Client
                print "Connecting to TIE."
                tie_client=TieClient(client)

                print "Trust Level is " + str(currentTrustLevel) + ". Updating TIE."

                reputations_dict = \
                tie_client.get_file_reputation({
                    HashType.MD5: currentMD5,
                    HashType.SHA1: currentSHA1,
                    HashType.SHA256: currentSHA256
                    })

                print reputations_dict

                #Check if there is an enterprise (custom set) reputation
                if (reputations_dict[FileProvider.ENTERPRISE]["trustLevel"]==TrustLevel.NOT_SET or \
                    reputations_dict[FileProvider.ENTERPRISE]["trustLevel"]==TrustLevel.UNKNOWN or \
                    reputations_dict[FileProvider.ENTERPRISE]["trustLevel"]==TrustLevel.MIGHT_BE_TRUSTED or \
                    reputations_dict[FileProvider.ENTERPRISE]["trustLevel"]==TrustLevel.MOST_LIKELY_TRUSTED):
                    
                    print "Current Trust Level is" + str(reputations_dict[FileProvider.ENTERPRISE]["trustLevel"])

                    #also, let's make sure GTI trustLevels are either not being queried, or set to Unknown
                    #we are nesting for clarity
                    if(FileProvider.GTI not in reputations_dict.keys() or reputations_dict[FileProvider.GTI]==TrustLevel.UNKNOWN):
                    
                        print "GTI either does not exist or set to UNKNOWN"

                        # If not set, go ahead and set it
                        tie_client.set_file_reputation(
                            TrustLevel.MOST_LIKELY_MALICIOUS, {
                                HashType.MD5: currentMD5,
                                HashType.SHA1: currentSHA1,
                                HashType.SHA256: currentSHA256},
                            filename=currentFilename,
                            comment="Reputation set via OpenDXL Cuckoo Integration. Cuckoo scored this sample a " + str(currentTrustLevel) + " out of 10.")
    
                        print "Reputation set for: " + str(currentFilename) + ": " + currentMD5

        except (TypeError, IOError) as e:
            raise CuckooReportError("Failed to update TIE with results: %s" % e)
