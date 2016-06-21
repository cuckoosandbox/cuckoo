"""Gatherer of software components for further identification by the Cuckoo
Sandbox team.

This file uploads as many relevant software components as possible so that the
Cuckoo Sandbox team may be able to add support for more versions of certain
software packages. E.g., currently we have special support for Office 2007,
Adobe PDF Reader 9, and Internet Explorer 8 - with the feedback from our users
we may be able to add special support for different versions of the same
software (think Office 2016, Internet Explorer Edge, etc).

This command should be ran with the "pipe=cuckoo,free=yes" option. You will
then find yourself with an analysis with all of the related dropped files.
This analysis should be "exported" (a feature from the Cuckoo Web Interface)
and shared with the Cuckoo Developers team in order to process the new files.

"""

import ctypes
import glob
import os

progfiles = [
    "Internet Explorer\\iexplore.exe",
    "Common Files\\Microsoft Shared\\VBA\\VBA*\\VBE*.dll",
    "Adobe\\Reader *\\Reader\\AcroRd32.dll",
    "Adobe\\Reader *\\Reader\\AcroRd32.exe",
    "Adobe\\Reader *\\Reader\\plug_ins\\escript.api",
]

system32 = [
    "mshtml.dll",
    "ncrypt.dll",
    "jscript.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "ntdll.dll",
    "advapi32.dll",
]

def report(filepath):
    buf = "FILE_NEW:%s" % filepath
    out = ctypes.create_string_buffer(512)
    value = ctypes.c_uint()

    ctypes.windll.kernel32.CallNamedPipeA(
        "\\\\.\\PIPE\\cuckoo", buf, len(buf),
        out, len(out), ctypes.byref(value), 1000
    )

if __name__ == "__main__":
    filepaths = []

    for filepath in progfiles:
        filepaths.append(os.path.join("C:\\Program Files", filepath))
        filepaths.append(os.path.join("C:\\Program Files (x86)", filepath))

    for filepath in system32:
        filepaths.append(os.path.join("C:\\Windows\\System32", filepath))
        filepaths.append(os.path.join("C:\\Windows\\Sysnative", filepath))

    for filepath in filepaths:
        if os.path.exists(filepath):
            report(filepath)
            continue

        if "*" in filepath:
            for filepath in glob.iglob(filepath):
                report(filepath)
            continue
