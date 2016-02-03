# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.

import logging
import os
from zipfile import BadZipfile

from lib.cuckoo.common.objects import File
from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError

try:
    from androguard.core.bytecodes.apk import APK
    HAVE_ANDROGUARD = True
except ImportError:
    HAVE_ANDROGUARD = False

try:
    from lib.api.googleplay.googleplay import GooglePlayAPI
    HAVE_GOOGLEPLAY = True
except ImportError:
    HAVE_GOOGLEPLAY = False

log = logging.getLogger(__name__)

class GooglePlay(Processing):
    """Google Play information about the analysis session"""

    def run(self):
        """Run Google play unofficial python api the get the google play information
        @return: list of google play features
        """
        self.key = "googleplay"
        googleplay = {}

        if not HAVE_GOOGLEPLAY:
            log.error("Unable to import the GooglePlay library, has it been "
                      "installed properly?")
            return

        if not HAVE_ANDROGUARD:
            log.error("Could not find the Androguard library, please install "
                      "it. (`pip install androguard`)")

        if ("file" not in self.task["category"]):
            return

        f = File(self.task["target"])
        if f.get_name().endswith((".zip", ".apk")) or "zip" in f.get_type():
            if not os.path.exists(self.file_path):
                raise CuckooProcessingError("Sample file doesn't exist: \"%s\"" % self.file_path)

            android_id = self.options.get("android_id")
            google_login = self.options.get("google_login")
            google_password = self.options.get("google_password")
            # auth_token = self.options.get("auth_token", None)

            if not android_id and not google_login and not google_password:
                raise CuckooProcessingError("Google Play Credentials not configured, skip")

            try:
                a = APK(self.file_path)
                if a.is_valid_APK():
                    package = a.get_package()
                    # Connect
                    api = GooglePlayAPI(android_id)
                    api.login(google_login, google_password, None)

                    # Get the version code and the offer type from the app details
                    app_data = api.details(package)
                    app_detail = app_data.docV2.details.appDetails

                    if not app_detail.installationSize:
                        return googleplay

                    googleplay["title"] = app_detail.title
                    googleplay["app_category"] = app_detail.appCategory._values
                    googleplay["version_code"] = app_detail.versionCode
                    googleplay["app_type"] = app_detail.appType
                    googleplay["content_rating"] = app_detail.contentRating
                    googleplay["developer_email"] = app_detail.developerEmail
                    googleplay["developer_name"] = app_detail.developerName
                    googleplay["developer_website"] = app_detail.developerWebsite
                    googleplay["installation_size"] = app_detail.installationSize
                    googleplay["num_downloads"] = app_detail.numDownloads
                    googleplay["upload_date"] = app_detail.uploadDate
                    googleplay["permissions"] = app_detail.permission._values
            except (IOError, OSError, BadZipfile) as e:
                raise CuckooProcessingError("Error opening file %s" % e)

        return googleplay
