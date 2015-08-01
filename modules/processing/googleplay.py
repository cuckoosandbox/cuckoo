# Copyright (C) Check Point Software Technologies LTD.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
from zipfile import BadZipfile

from analyzer.android_on_linux.lib.api.androguard import apk
from lib.cuckoo.common.objects import File
from analyzer.android_on_linux.lib.core.packages import choose_package
from lib.api.googleplay.googleplay import GooglePlayAPI
from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError


class GooglePlay(Processing):
    """Google Play information about the analysis session"""

    def run(self):
        """Run Google play unofficial python api the get the google play information
        @return: list of google play features
        """
        self.key = "googleplay"
        googleplay = {}

        if ("file" not in self.task["category"]):
            return

        if("apk" in choose_package(File(self.task["target"]).get_type(),File(self.task["target"]).get_name())):
            if not os.path.exists(self.file_path):
                raise CuckooProcessingError("Sample file doesn't exist: \"%s\"" % self.file_path)

            android_id =self.options.get("android_id", None)
            google_login = self.options.get("google_login", None)
            google_password = self.options.get("google_password", None)
            #auth_token = self.options.get("auth_token", None)

            if not (android_id or google_login or google_password):
                raise CuckooProcessingError("Google Play Credentials not configured, skip")

            try :
                a = apk.APK(self.file_path)
                if a.is_valid_APK():
                    package=a.get_package()
                    # Connect
                    api = GooglePlayAPI(android_id)
                    api.login(google_login, google_password, None)

                    # Get the version code and the offer type from the app details
                    app_data = api.details(package)
                    app_detail = app_data.docV2.details.appDetails

                    if(app_detail.installationSize==0):
                        return googleplay

                    googleplay["title"]=app_detail.title
                    googleplay["app_category"]=app_detail.appCategory._values
                    googleplay["version_code"]=app_detail.versionCode
                    googleplay["app_type"]=app_detail.appType
                    googleplay["content_rating"]=app_detail.contentRating
                    googleplay["developer_email"]=app_detail.developerEmail
                    googleplay["developer_name"]=app_detail.developerName
                    googleplay["developer_website"]=app_detail.developerWebsite
                    googleplay["installation_size"]=app_detail.installationSize
                    googleplay["num_downloads"]=app_detail.numDownloads
                    googleplay["upload_date"]=app_detail.uploadDate
                    googleplay["permissions"]=app_detail.permission._values

            except (IOError, OSError,BadZipfile) as e:
                raise CuckooProcessingError("Error opening file %s" % e)

        return googleplay
