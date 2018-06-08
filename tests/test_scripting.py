# Copyright (C) 2017-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock

from cuckoo.common.scripting import CmdExe, PowerShell, Scripting

class TestCmdExe(object):
    def setup(self):
        self.cmd = CmdExe()

    def test_exe_regex(self):
        assert self.cmd.program == "cmd"
        assert self.cmd.match_command("cmd") is True
        assert self.cmd.match_command("CMD.EXE") is True
        assert self.cmd.match_command("command.exe") is False

    def test_cmd_c(self):
        assert self.cmd.parse_command_line(
            "cmd.exe /c ping 8.8.8.8"
        ) == {
            "remains": False,
            "command": ["ping", "8.8.8.8"],
        }
        assert self.cmd.parse_command_line(
            "cmd.exe /C ping 8.8.8.8"
        ) == {
            "remains": False,
            "command": ["ping", "8.8.8.8"],
        }

    def test_cmd_k(self):
        assert self.cmd.parse_command_line(
            "cmd.exe /k ping 8.8.8.8"
        ) == {
            "remains": True,
            "command": ["ping", "8.8.8.8"],
        }
        assert self.cmd.parse_command_line(
            "cmd.exe /K ping 8.8.8.8"
        ) == {
            "remains": True,
            "command": ["ping", "8.8.8.8"],
        }

    def test_cmd_k_quoted(self):
        assert self.cmd.parse_command_line(
            'cmd.exe "/k ping 8.8.8.8"'
        ) == {
            "remains": True,
            "command": ["ping", "8.8.8.8"],
        }

    def test_cmd_q(self):
        assert self.cmd.parse_command_line(
            "cmd.exe /q /c ping 8.8.8.8"
        ) == {
            "quiet": True,
            "remains": False,
            "command": ["ping", "8.8.8.8"],
        }
        assert self.cmd.parse_command_line(
            "cmd.exe /Q /c ping 8.8.8.8"
        ) == {
            "quiet": True,
            "remains": False,
            "command": ["ping", "8.8.8.8"],
        }

    @mock.patch("cuckoo.common.scripting.log")
    def test_unhandled(self, p):
        assert self.cmd.parse_command_line(
            "cmd.exe this not handled",
        ) == {}
        assert p.warning.call_count == 3

class TestPowerShell(object):
    def setup(self):
        self.ps1 = PowerShell()

    def test_exe_regex(self):
        assert self.ps1.program == "powershell"
        assert self.ps1.match_command("poWerSheLl.eXe")
        assert self.ps1.match_command("powershell")
        assert self.ps1.match_command("powershell.exe")
        assert self.ps1.match_command("POWERSHELL.EXE")
        assert self.ps1.match_command("PoWerShell")

        assert self.ps1.match_command(
            "c:\\windows\\syswow64\\windowspowershell\\v1.0\\powershell.exe"
        )
        assert self.ps1.match_command(
            '"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"'
        )
        assert self.ps1.match_command(
            '"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell_ise.exe"'
        )
        assert self.ps1.match_command(
            "C:\\Windows\\sysnative\\WindowsPowerShell\\v1.0\\powershell.exe"
        )
        assert self.ps1.match_command(
            'C:\\\\windows\\\\syswow64\\\\windowspowershell\\\\v1.0\\\\powershell.exe'
        )

    def test_cmdparse_encodedcommand(self):
        assert self.ps1._cmdparse_encodedcommand(
            ["-encodedcommand"], 0
        ) == (1, None)

        assert self.ps1._cmdparse_encodedcommand(
            ["-encodedcommand", "a"], 0
        ) == (1, None)

        assert self.ps1._cmdparse_encodedcommand(
            ["-encodedcommand", "YWJj"], 0
        ) == (1, None)

    def test_cmdparse_windowstyle(self):
        assert self.ps1._cmdparse_windowstyle(
            ["-windowstyle"], 0
        ) == (1, None)

    def test_parse_cmdline_command(self):
        assert self.ps1.parse_command_line(
            "powershell.exe -c ping 8.8.8.8"
        ) == {
            "command": "ping 8.8.8.8",
        }

        assert self.ps1.parse_command_line(
            "powershell -c $s=New-Object IO.MemoryStream(,"
            "[Convert]::FromBase64String('aGVsbG8='));"
        ) == {
            "command": (
                "$s=New-Object IO.MemoryStream(,"
                "[Convert]::FromBase64String('aGVsbG8='));"
            ),
        }

    def test_parse_cmdline_encodedcommand(self):
        assert self.ps1.parse_command_line(
            "powershell.exe -EncodedCommand ZQBjAGgAbwAgACIARABvAHIAbwB0AGgAeQAiAA=="
        ) == {
            "encodedcommand": 'echo "Dorothy"',
        }
        assert self.ps1.parse_command_line(
            "powershell.exe -eNco ZQBjAGgAbwAgACIAVwBpAHoAYQByAGQAIgA="
        ) == {
            "encodedcommand": 'echo "Wizard"',
        }
        assert self.ps1.parse_command_line(
            "powershell.exe -^e^C^ ZQBjAGgAbwAgACIAVwBpAHQAYwBoACIA"
        ) == {
            "encodedcommand": 'echo "Witch"',
        }
        assert self.ps1.parse_command_line(
            "powershell.exe -e ZgBvAG8AIABiAGEAcgA=",
        ) == {
            "encodedcommand": "foo bar",
        }

    def test_parse_cmdline_windowstyle(self):
        assert self.ps1.parse_command_line(
            "powershell.exe -window hidden",
        ) == {
            "windowstyle": "hidden",
        }
        assert self.ps1.parse_command_line(
            "powershell.exe -W Hidden",
        ) == {
            "windowstyle": "hidden",
        }
        assert self.ps1.parse_command_line(
            "powershell.exe -wind hiddeN",
        ) == {
            "windowstyle": "hidden",
        }

    def test_parse_cmdline_noninteractive(self):
        assert self.ps1.parse_command_line(
            "powershell.exe -Noni",
        ) == {
            "noninteractive": True,
        }
        assert self.ps1.parse_command_line(
            "powershell.exe -noninteractive",
        ) == {
            "noninteractive": True,
        }

    def test_parse_cmdline_noprofile(self):
        assert self.ps1.parse_command_line(
            "powershell.exe -nop",
        ) == {
            "noprofile": True,
        }
        assert self.ps1.parse_command_line(
            "powershell.exe -NoProfile",
        ) == {
            "noprofile": True,
        }
        assert self.ps1.parse_command_line(
            "powershell.exe -noP",
        ) == {
            "noprofile": True,
        }

    def test_parse_cmdline_executionprofile(self):
        assert self.ps1.parse_command_line(
            "powershell.exe -ep bypass",
        ) == {
            "executionpolicy": "bypass",
        }
        assert self.ps1.parse_command_line(
            "powershell.exe -Ep BYPASS",
        ) == {
            "executionpolicy": "bypass",
        }
        assert self.ps1.parse_command_line(
            "powershell.exe -ExecuTionPolicy ByPasS",
        ) == {
            "executionpolicy": "bypass",
        }

    def test_parse_cmdline_misc(self):
        assert self.ps1.parse_command_line(
            "powershell.exe -sta"
        ) == {
            "sta": True,
        }
        assert self.ps1.parse_command_line(
            "powershell.exe -noexit"
        ) == {
            "noexit": True,
        }
        assert self.ps1.parse_command_line(
            "powershell.exe -nologo"
        ) == {
            "nologo": True,
        }

    def test_parse_cmdline_powershell(self):
        assert self.ps1.parse_command_line(
            "powershell.exe PowerShell.exe powershell -nologo"
        ) == {
            "command": "PowerShell.exe powershell -nologo",
        }

        assert self.ps1.parse_command_line(
            "PowerShell.exe powershell -nologo"
        ) == {
            "command": "powershell -nologo",
        }

        assert self.ps1.parse_command_line(
            "powershell -nologo"
        ) == {
            "nologo": True,
        }

    def test_parse_remainder(self):
        assert self.ps1.parse_command_line(
            "powershell start-process ping.exe 8.8.8.8"
        ) == {
            "command": "start-process ping.exe 8.8.8.8",
        }

class TestScripting(object):
    def setup(self):
        self.scr = Scripting()

    def test_cmd_ping(self):
        obj = self.scr.parse_command("cmd /c ping 8.8.8.8")
        assert obj.program == "cmd"
        assert obj.ext == "bat"
        assert obj.args == {
            "remains": False,
            "command": ["ping", "8.8.8.8"],
        }
        assert not obj.children
        assert obj.astree() == {
            "args": {
                "remains": False,
                "command": ["ping", "8.8.8.8"],
            },
            "children": [],
        }

    def test_cmd_fullpath(self):
        obj = self.scr.parse_command(
            "C:\\\\Windows\\\\System32\\\\cmd.exe /k ping 8.8.8.8"
        )
        assert obj.program == "cmd"
        assert obj.ext == "bat"
        assert obj.args == {
            "remains": True,
            "command": [
                "ping", "8.8.8.8",
            ],
        }

    def test_cmd_cmd_cmd_ping(self):
        obj = self.scr.parse_command(
            "cmd /c CMD.EXE /c cmd.exE /c ping 8.8.8.8"
        )
        assert obj.program == "cmd"
        assert obj.ext == "bat"
        assert obj.args == {
            "remains": False,
            "command": ["CMD.EXE", "/c", "cmd.exE", "/c", "ping", "8.8.8.8"],
        }
        assert len(obj.children) == 1
        assert obj.children[0].args == {
            "remains": False,
            "command": ["cmd.exE", "/c", "ping", "8.8.8.8"],
        }
        assert len(obj.children[0].children) == 1
        assert obj.children[0].children[0].args == {
            "remains": False,
            "command": ["ping", "8.8.8.8"],
        }
        assert not obj.children[0].children[0].children
        assert obj.astree() == {
            "args": {
                "remains": False,
                "command": [
                    "CMD.EXE", "/c", "cmd.exE", "/c", "ping", "8.8.8.8",
                ],
            },
            "children": [{
                "args": {
                    "remains": False,
                    "command": ["cmd.exE", "/c", "ping", "8.8.8.8"],
                },
                "children": [{
                    "args": {
                        "remains": False,
                        "command": ["ping", "8.8.8.8"],
                    },
                    "children": [],
                }],
            }],
        }

    def test_cmd_powershell(self):
        obj = self.scr.parse_command("""
            cmd /c powershell -nop -ep bypass -enc
            ZQBjAGgAbwAgACIAUgBlAGMAdQByAHMAaQB2AGUAIgA=
        """)
        assert obj.program == "cmd"
        assert obj.ext == "bat"
        assert obj.args == {
            "remains": False,
            "command": [
                "powershell", "-nop", "-ep", "bypass", "-enc",
                "ZQBjAGgAbwAgACIAUgBlAGMAdQByAHMAaQB2AGUAIgA=",
            ]
        }
        assert len(obj.children) == 1
        assert obj.children[0].args == {
            "noprofile": True, "executionpolicy": "bypass",
            "encodedcommand": 'echo "Recursive"',
        }
        assert not obj.children[0].children

    def test_powershell_encodedcommand(self):
        obj = self.scr.parse_command("""
            powershell -nop -ep bypass -enc
            ZQBjAGgAbwAgACIAUgBlAGMAdQByAHMAaQB2AGUAIgA=
        """)
        assert obj.program == "powershell"
        assert obj.ext == "ps1"
        assert obj.args == {
            "noprofile": True, "executionpolicy": "bypass",
            "encodedcommand": 'echo "Recursive"',
        }
        assert not obj.children
        assert obj.get_script() == 'echo "Recursive"'

    def test_powershell_command(self):
        obj = self.scr.parse_command("""
            powershell -nop -ep bypass -Command ping '8.8.8.8'
        """)
        assert obj.program == "powershell"
        assert obj.ext == "ps1"
        assert obj.get_script() == "ping '8.8.8.8'"
