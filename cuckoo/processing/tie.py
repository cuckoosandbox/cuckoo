# Copyright (C) 2017 Jesse Netz.
#

import logging
import os

#These are required for DXL integration
import sys
import json
import base64

log = logging.getLogger(__name__)

#cuckoo imports
from cuckoo.common.abstracts import Processing
from cuckoo.common.objects import File
from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.common.exceptions import CuckooProcessingError


#DXL and TIE imports
from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxlclient.message import Message, Request
from dxltieclient import TieClient
from dxltieclient.constants import HashType, ReputationProp, FileProvider, FileEnterpriseAttrib, CertProvider, CertEnterpriseAttrib, AtdAttrib, TrustLevel, EpochMixin

# Config file name and location
CONFIG_FILE_NAME = "dxlclient.config"
CONFIG_FILE = "/etc/opendxl/" + CONFIG_FILE_NAME
# Create DXL configuration from file
config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)


# The topic for requesting file reputations
FILE_REP_TOPIC = "/mcafee/service/tie/file/reputation"


class TIE(Processing):
    """Gets reputation values from McAfee TIE environment for various results.

    """
    order = 2
    def trustLevel(self, trustint):
        """
        Returns the written trust level based on its numerical value
        :param trustnum: The trust integer to convert to written form
        :return: The written form for the specified trust integet
        """
        if trustint == TrustLevel.KNOWN_TRUSTED_INSTALLER:
            return "Known Trusted Installer"
        elif trustint >= TrustLevel.KNOWN_TRUSTED:
            return "Known Trusted"
        elif trustint >= TrustLevel.MOST_LIKELY_TRUSTED:
            return "Most Likely Trusted"
        elif trustint >= TrustLevel.MIGHT_BE_TRUSTED:
            return "Might Be Trusted"
        elif trustint >= TrustLevel.UNKNOWN:
            return "Unknown"
        elif trustint >= TrustLevel.MIGHT_BE_MALICIOUS:
            return "Might Be Malicious"
        elif trustint >= TrustLevel.MOST_LIKELY_MALICIOUS:
            return "Most Likely Malicious"
        elif trustint >= TrustLevel.KNOWN_MALICIOUS:
            return "Known Malicious"
        else:
            return "Not Set"

        return "Not Set"


    def run(self):

        """Runs TIE processing
        @return: TIE results
        """
        log.info("Processing TIE reputation analysis.")

        self.key = "tie"
        timeout = int(self.options.get("timeout", 60))
        scan = int(self.options.get("scan", 0))

        # Evaluate the original sample against TIE reputation
        if self.task["category"] == "file":
            # Create the client
            with DxlClient(config) as client:
                # Connect to the fabric
                client.connect()

                tie_client = TieClient(client)

                #Generate relevant hash information
                md5_hex=File(self.file_path).get_md5()
                sha1_hex=File(self.file_path).get_sha1()
                sha256_hex=File(self.file_path).get_sha256()

                #Request raw json reputation results
                reputations_dict = \
                        tie_client.get_file_reputation({
                        HashType.MD5: md5_hex,
                        HashType.SHA1: sha1_hex,
                        HashType.SHA256: sha256_hex
                        })

				#debug
                log.info("Raw TIE results: " + json.dumps(reputations_dict, sort_keys=True, indent=4, separators=(',', ': ')))

                #initialize result array and tiekey counter for each result
                proc_result = {}
                tiekey = 0
		strtiekey = str(tiekey)
                # Display the Global Threat Intelligence 
                if FileProvider.GTI in reputations_dict:
                    gti_rep = reputations_dict[FileProvider.GTI]
                    proc_result[strtiekey]={}
                    proc_result[strtiekey]['title']="Global Threat Intelligence (GTI) Test Date:"
                    proc_result[strtiekey]['value']= EpochMixin.to_localtime_string(gti_rep[ReputationProp.CREATE_DATE])
                    tiekey += 1
                    strtiekey = str(tiekey)

                    #Set GTI Trust Level
                    proc_result[strtiekey]={}
                    proc_result[strtiekey]['title']="Global Threat Intelligence (GTI) trust level:"
                    trustValue=gti_rep[ReputationProp.TRUST_LEVEL]
                    proc_result[strtiekey]['value']= self.trustLevel(trustValue)
                    tiekey += 1
                    strtiekey = str(tiekey)



                # Display the Enterprise reputation information
                if FileProvider.ENTERPRISE in reputations_dict:
                    ent_rep = reputations_dict[FileProvider.ENTERPRISE]

                    # Retrieve the enterprise reputation attributes
                    ent_rep_attribs = ent_rep[ReputationProp.ATTRIBUTES]

                    # Display prevalence (if it exists)
                    if FileEnterpriseAttrib.PREVALENCE in ent_rep_attribs:
                        proc_result[strtiekey]={}
                        proc_result[strtiekey]['title'] = "Enterprise prevalence:"
                        proc_result[strtiekey]['value'] =  ent_rep_attribs[FileEnterpriseAttrib.PREVALENCE]
                        tiekey += 1
                        strtiekey = str(tiekey)

                    # Display first contact date (if it exists)
                    if FileEnterpriseAttrib.FIRST_CONTACT in ent_rep_attribs:
                        proc_result[strtiekey]={}
                        proc_result[strtiekey]['title'] =  "First contact: "
                        proc_result[strtiekey]['value'] =  FileEnterpriseAttrib.to_localtime_string(ent_rep_attribs[FileEnterpriseAttrib.FIRST_CONTACT])
                        tiekey += 1
                        strtiekey = str(tiekey)


                #These are lookup conversions for the ATD trust_score
                valueDict = {}
                valueDict['-1']="Known Trusted"
                valueDict['0']="Most Likely Trusted"
                valueDict['1']="Might Be Trusted"
                valueDict['2']="Unknown"
                valueDict['3']="Might Be Malicious"
                valueDict['4']="Most Likely Malicious"
                valueDict['5']="Known Malicious"
                valueDict['-2']="Not Set"


                # Display the ATD reputation information
                if FileProvider.ATD in reputations_dict:
                    atd_rep = reputations_dict[FileProvider.ATD]

                    # Retrieve the ATD reputation attributes
                    atd_rep_attribs = atd_rep[ReputationProp.ATTRIBUTES]

                    proc_result[strtiekey]={}
                    proc_result[strtiekey]['title'] = "ATD Test Date: "
                    proc_result[strtiekey]['value']= EpochMixin.to_localtime_string(atd_rep[ReputationProp.CREATE_DATE])
                    tiekey += 1
                    strtiekey = str(tiekey)

                    # Display GAM Score (if it exists)
                    if AtdAttrib.GAM_SCORE in atd_rep_attribs:
                        proc_result[strtiekey]={}
                        proc_result[strtiekey]['title'] = "ATD Gateway AntiMalware Score: "
                        proc_result[strtiekey]['value'] =  valueDict[atd_rep_attribs[AtdAttrib.GAM_SCORE]]
                        tiekey += 1
                        strtiekey = str(tiekey)

                    # Display AV Engine Score (if it exists)
                    if AtdAttrib.AV_ENGINE_SCORE in atd_rep_attribs:
                        proc_result[strtiekey]={}
                        proc_result[strtiekey]['title'] = "ATD AV Engine Score: "
                        proc_result[strtiekey]['value'] = valueDict[atd_rep_attribs[AtdAttrib.AV_ENGINE_SCORE]]
                        tiekey += 1
                        strtiekey = str(tiekey)

                    # Display Sandbox Score (if it exists)
                    if AtdAttrib.SANDBOX_SCORE in atd_rep_attribs:
                        proc_result[strtiekey]={}
                        proc_result[strtiekey]['title'] = "ATD Sandbox Score: "
                        proc_result[strtiekey]['value'] = valueDict[atd_rep_attribs[AtdAttrib.SANDBOX_SCORE]]
                        tiekey += 1
                        strtiekey = str(tiekey)

                    # Display Verdict (if it exists)
                    if AtdAttrib.VERDICT in atd_rep_attribs:
                        proc_result[strtiekey]={}
                        proc_result[strtiekey]['title'] = "ATD Verdict: "
                        proc_result[strtiekey]['value'] = valueDict[atd_rep_attribs[AtdAttrib.VERDICT]]
                        tiekey += 1
                        strtiekey = str(tiekey)

                results=proc_result

        elif self.task["category"] == "url":
            return
        elif self.task["category"] == "baseline":
            return
        elif self.task["category"] == "service":
            return
        else:
            raise CuckooProcessingError("Unsupported task category: %s" %
                                        self.task["category"])


        log.info("Finished processing TIE reputation analysis.")
        return results
