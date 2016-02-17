# Copyright (C) 2014-2016 Cuckoo Foundation.
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

    file_type = file_type.lower()
    file_name = file_name.lower()

    if "apk" in file_name:
        return "apk"
    elif "zip" in file_type:
        return "apk"
    # elif "DEX" in file_type:
    #    return "dex"
    else:
        return "apk"
