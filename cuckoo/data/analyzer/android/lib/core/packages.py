# Copyright (C) 2014-2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.

def choose_package(file_type, file_name):
    """Choose analysis package due to file type and file extension.
    @param file_type: file type.
    @return: package or None.
    """
    if not file_type:
        return None

    if "JAR" in file_type or \
            "Zip" in file_type or \
            "apk" in file_name:
        return "apk"
    else:
        return None
