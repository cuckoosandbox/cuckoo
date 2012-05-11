def choose_package(file_type):
    if "DLL" in file_type:
        return "dll"
    elif "PE32" in file_type or "MS-DOS" in file_type:
        return "exe"
    elif "PDF" in file_type:
        return "pdf"
    else:
        return None