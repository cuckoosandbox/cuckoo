def choose_package(file_type):
    if not file_type:
        return None

    if "DLL" in file_type:
        return "dll"
    elif "PE32" in file_type or "MS-DOS" in file_type:
        return "exe"
    elif "PDF" in file_type:
        return "pdf"
    elif "Rich Text Format" in file_type:
        return "doc"
    elif "Microsoft Excel" in file_type:
        return "xls"
    else:
        return None
