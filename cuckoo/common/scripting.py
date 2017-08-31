# Copyright (C) 2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import binascii
import logging
import re
import shlex

log = logging.getLogger(__name__)

class Scripting(object):
    program = None
    ext = None

    def __init__(self, parent=None):
        self.parent = parent
        self.args = {}
        self.children = []

    def shlex(self, cmdline):
        if isinstance(cmdline, (tuple, list)):
            return cmdline
        try:
            return shlex.split(cmdline, posix=False)
        except ValueError:
            log.warning("Error parsing command-line: %s", cmdline)
            return []

    def match_command(self, program):
        return bool(re.match(self.EXE_REGEX, program, re.I))

    def parse_command(self, cmdline):
        cmdline = self.shlex(cmdline)
        if not cmdline:
            return

        for cls in Scripting.__subclasses__():
            obj = cls(self)
            if obj.match_command(cmdline[0]):
                obj.args = obj.parse_command_line(cmdline)
                self.children.append(obj)
                return obj

    def astree(self):
        return {
            "args": self.args,
            "children": [child.astree() for child in self.children],
        }

    def parse_command_line(self, cmdline):
        raise NotImplementedError

    def get_script(self):
        raise NotImplementedError

class CmdExe(Scripting):
    EXE_REGEX = "cmd(\\.exe)?$"

    program = "cmd"
    ext = "bat"

    def parse_command_line(self, cmdline):
        cmdline = self.shlex(cmdline)

        idx, ret = 1, {}

        while idx < len(cmdline):
            if cmdline[idx] == "/c":
                ret["command"] = cmdline[idx+1:]
                self.parse_command(cmdline[idx+1:])
                break

            log.warning(
                "Unhandled cmd.exe command-line argument(s): %s",
                cmdline[idx:]
            )
            idx += 1

        return ret

    def get_script(self):
        return " ".join(self.args.get("command", []))

def ps1_cmdarg(s, minimum=1):
    """Creates an exactly matching PowerShell command line argument regex,
    instead of a regex that matches anything with the same characters."""
    return "".join(
        "([%s%s^]" % (ch.lower(), ch.upper()) for ch in s
    ) + ")?"*(len(s)-minimum) + ")"*minimum

class PowerShell(Scripting):
    EXE_REGEX = (
        "([\"]?C:(\\\\)+Windows(\\\\)+(System32|syswow64|sysnative)"
        "(\\\\)+WindowsPowerShell(\\\\)+v1\\.0(\\\\)+)?"
        "powershell(_ise)?(\\.exe)?"
        "[\"]?$"
    )

    program = "powershell"
    ext = "ps1"

    CMDLINE_REGEX = {
        "command": "\\-[\\^]?%s$" % ps1_cmdarg("command"),
        "encodedcommand": "\\-[\\^]?%s$" % ps1_cmdarg("encodedcommand"),
        "windowstyle": "\\-[\\^]?%s$" % ps1_cmdarg("windowstyle"),
        "noninteractive": "\\-[\\^]?%s$" % ps1_cmdarg("noninteractive", 4),
        "noprofile": "\\-[\\^]?%s$" % ps1_cmdarg("noprofile", 3),
        "executionpolicy": (
            "\\-[\\^]?([eE][pP]|%s)$" % ps1_cmdarg("executionpolicy", 2)
        ),
        "sta": "\\-[\\^]?sta$",
        "noexit": "\\-[\\^]?noexit$",
        "nologo": "\\-[\\^]?%s$" % ps1_cmdarg("nologo", 3),
    }

    def _cmdparse_command(self, cmdline, idx):
        return len(cmdline)-idx, " ".join(cmdline[idx+1:])

    def _cmdparse_encodedcommand(self, cmdline, idx):
        try:
            return 1, cmdline[idx+1].decode("base64").decode("utf16")
        except (IndexError, binascii.Error, UnicodeDecodeError):
            pass
        return 1, None

    def _cmdparse_windowstyle(self, cmdline, idx):
        try:
            if re.match(ps1_cmdarg("hidden", 3), cmdline[idx+1]):
                return 1, "hidden"
        except IndexError:
            pass
        return 1, None

    def _cmdparse_executionpolicy(self, cmdline, idx):
        try:
            return 1, cmdline[idx+1].lower()
        except IndexError:
            pass
        return 1, None

    def parse_command_line(self, cmdline):
        cmdline = self.shlex(cmdline)

        idx, ret = 1, {}

        while idx < len(cmdline):
            for key, regex in self.CMDLINE_REGEX.items():
                if not re.match(regex, cmdline[idx]):
                    continue

                fn = getattr(self, "_cmdparse_%s" % key, None)
                used, value = fn(cmdline, idx) if fn else (0, True)

                ret[key] = value
                idx += used + 1
                break
            else:
                break

        # Handle trailing fields which are interpreted as commands.
        if idx < len(cmdline) and not self.get_script():
            ret["command"] = " ".join(cmdline[idx:])

        return ret

    def get_script(self):
        return self.args.get("command") or self.args.get("encodedcommand")
