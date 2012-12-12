# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

def choose_package(file_type, file_name):
    """Choose analysis package due to file type.
    @param file_type: file type.
    @return: package or None.
    """
    if not file_type:
        return None

    if "DLL" in file_type:
        return "dll"
    elif "PE32" in file_type or "MS-DOS" in file_type:
        return "exe"
    elif "PDF" in file_type:
        return "pdf"
    elif "Rich Text Format" in file_type or "Microsoft Office Word" in file_type or file_name.endswith(".docx"):
        return "doc"
    elif "Microsoft Office Excel" in file_type or file_name.endswith(".xlsx"):
        return "xls"
    else:
        return None
