# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
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
    elif "PDF" in file_type or file_name.endswith(".pdf"):
        return "pdf"
    elif "Rich Text Format" in file_type or "Microsoft Office Word" in file_type or ("Composite Document File" in file_type and not "Installer" in file_type) or file_name.endswith(".docx") or file_name.endswith(".doc"):
        return "doc"
    elif "Microsoft Office Excel" in file_type or file_name.endswith(".xlsx") or file_name.endswith(".xls"):
        return "xls"
    elif "HTML" in file_type or file_name.endswith(".htm") or file_name.endswith(".html"):
        return "html"
    elif file_name.endswith(".jar"):
        return "jar"
    else:
        return "generic"
