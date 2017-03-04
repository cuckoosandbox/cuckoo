# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import mock
import os.path
import pytest
import tempfile

from cuckoo.common.exceptions import CuckooProcessingError
from cuckoo.core.database import Database
from cuckoo.main import cuckoo_create
from cuckoo.misc import set_cwd
from cuckoo.processing.behavior import ProcessTree
from cuckoo.processing.debug import Debug
from cuckoo.processing.network import Pcap
from cuckoo.processing.network import Pcap2
from cuckoo.processing.platform.windows import RebootReconstructor
from cuckoo.processing.screenshots import Screenshots
from cuckoo.processing.static import Static
from cuckoo.processing.strings import Strings
from cuckoo.processing.virustotal import VirusTotal

db = Database()

class TestProcessing(object):
    def test_debug(self):
        set_cwd(tempfile.mkdtemp())

        db.connect(dsn="sqlite:///:memory:")
        db.add_url("http://google.com/")
        db.add_error("foo", 1)
        db.add_error("bar", 1)

        d = Debug()
        d.task = {
            "id": 1,
        }
        d.log_path = "nothing_to_see_here"
        d.cuckoolog_path = "neither here"
        d.mitmerr_path = "no no no"

        results = d.run()
        assert len(list(results["errors"])) == len(results["errors"])
        assert results["errors"] == ["foo", "bar"]
        assert results["action"] == []

        db.add_error("err", 1, "thisisanaction")
        results = d.run()
        assert results["action"] == ["thisisanaction"]

    def test_pdf(self):
        set_cwd(tempfile.mkdtemp())

        s = Static()
        s.set_task({
            "category": "file",
            "package": "pdf",
            "target": "pdf0.pdf",
        })
        s.set_options({
            "pdf_timeout": 30,
        })
        s.file_path = "tests/files/pdf0.pdf"
        r = s.run()["pdf"][0]
        assert "var x = unescape" in r["javascript"][0]["orig_code"]

    def test_pdf_metadata(self):
        set_cwd(tempfile.mkdtemp())

        s = Static()
        s.set_task({
            "category": "file",
            "package": "pdf",
            "target": "pdf-sample.pdf",
        })
        s.set_options({
            "pdf_timeout": 30,
        })
        s.file_path = "tests/files/pdf-sample.pdf"
        obj = s.run()["pdf"]
        assert len(obj) == 2
        assert obj[1] == {
            "author": "cdaily",
            "creation": "D:20000629102108+11'00'",
            "creator": "Microsoft Word 8.0",
            "javascript": [],
            "modification": "2013-10-28T15:24:13-04:00",
            "producer": "Acrobat Distiller 4.0 for Windows",
            "subject": "",
            "title": "This is a test PDF file",
            "urls": [],
            "version": 1,
        }

    def test_office(self):
        s = Static()
        s.set_task({
            "category": "file",
            "package": "doc",
            "target": "createproc1.docm",
        })
        s.file_path = "tests/files/createproc1.docm"
        r = s.run()["office"]
        assert "ThisDocument" in r["macros"][0]["orig_code"]
        assert "Sub AutoOpen" in r["macros"][1]["orig_code"]
        assert 'process.Create("notepad.exe"' in r["macros"][1]["orig_code"]

    def test_strings(self):
        s = Strings()
        s.set_task({
            "category": "file",
        })

        fd, filepath = tempfile.mkstemp()
        os.write(fd, "ABCDEFGH\n"*0x1000)
        os.close(fd)

        s.file_path = filepath
        assert len(s.run()) == s.MAX_STRINGCNT

        fd, filepath = tempfile.mkstemp()
        os.write(fd, ("%s\n" % ("A"*0x1000)) * 200)
        os.close(fd)

        s.file_path = filepath
        strings = s.run()
        assert len(strings) == 200
        assert len(strings[0]) == s.MAX_STRINGLEN
        assert len(strings[42]) == s.MAX_STRINGLEN
        assert len(strings[199]) == s.MAX_STRINGLEN

    @mock.patch("cuckoo.processing.screenshots.log")
    def test_screenshot_tesseract(self, p):
        s = Screenshots()
        # Use an empty directory so no actual screenshot analysis is done.
        s.shots_path = tempfile.mkdtemp()
        s.set_options({
            "tesseract": None,
        })
        assert s.run() == []
        p.error.assert_not_called()

        s.set_options({
            "tesseract": "no",
        })
        assert s.run() == []
        p.error.assert_not_called()

        s.set_options({
            "tesseract": "thispathdoesnotexist",
        })
        assert s.run() == []
        p.error.assert_called_once()

    @mock.patch("cuckoo.processing.screenshots.subprocess")
    def test_screenshots(self, p):
        s = Screenshots()
        s.shots_path = os.path.join(
            "tests", "files", "sample_analysis_storage", "shots"
        )
        s.set_options({
            "tesseract": __file__,
        })
        p.check_output.return_value = "foobar"
        assert s.run() == [{
            "path": os.path.join(s.shots_path, "0001.jpg"),
            "ocr": "foobar",
        }]
        p.check_output.assert_called_once_with([
            __file__, os.path.join(s.shots_path, "0001.jpg"), "stdout"
        ])
        shotpath = os.path.join(
            "tests", "files", "sample_analysis_storage",
            "shots", "0001_small.jpg"
        )
        assert os.path.exists(shotpath)
        os.unlink(shotpath)

    @mock.patch("cuckoo.processing.screenshots.subprocess")
    @mock.patch("cuckoo.processing.screenshots.log")
    def test_ignore_notesseract(self, p, q):
        s = Screenshots()
        s.shots_path = os.path.join(
            "tests", "files", "sample_analysis_storage", "shots"
        )
        s.set_options({
            "tesseract": "no",
        })
        assert len(s.run()) == 1
        p.error.assert_not_called()
        p.warning.assert_not_called()
        q.check_output.assert_not_called()
        shotpath = os.path.join(
            "tests", "files", "sample_analysis_storage",
            "shots", "0001_small.jpg"
        )
        assert os.path.exists(shotpath)
        os.unlink(shotpath)

    def test_virustotal_nokey(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create(cfg={
            "processing": {
                "virustotal": {
                    "key": None,
                },
            },
        })
        with pytest.raises(CuckooProcessingError) as e:
            VirusTotal().run()
        e.match("API key not configured")

    def test_virustotal_invalidcategory(self):
        set_cwd(tempfile.mkdtemp())
        cuckoo_create()
        with pytest.raises(CuckooProcessingError) as e:
            v = VirusTotal()
            v.set_task({
                "category": "notacategory",
            })
            v.run()
        e.match("Unsupported task category")

class TestBehavior(object):
    def test_process_tree_regular(self):
        pt = ProcessTree(None)

        l = [
            (484, 380, False),
            (1444, 1872, True),
            (2068, 1444, True),
            (2104, 1444, True),
            (2292, 2068, True),
            (2348, 2292, True),
            (2428, 2068, True),
            (2488, 2428, True),
            (2564, 2068, True),
            (2620, 2068, True),
        ]

        for idx, (pid, ppid, track) in enumerate(l):
            pt.handle_event({
                "pid": pid,
                "ppid": ppid,
                "process_name": "procname",
                "command_line": "cmdline",
                "first_seen": idx,
                "children": [],
                "track": track,
            })

        obj = pt.run()
        assert len(obj) == 2
        assert not obj[0]["children"]
        assert len(obj[1]["children"]) == 2
        assert len(obj[1]["children"][0]["children"]) == 4
        assert len(obj[1]["children"][0]["children"][0]["children"]) == 1

    def test_process_tree_pid_reuse(self):
        pt = ProcessTree(None)

        # Parent PID of the initial malicious process (pid=2624) is later on
        # created again, confusing our earlier code and therefore not
        # displaying any of the malicious processes in our Web Interface.
        l = [
            (468, 364, False),
            (2624, 2104, True),
            (2148, 2624, True),
            (1836, 1788, True),
            (2056, 2148, True),
            (2104, 2148, True),
            (2480, 2104, True),
            (2420, 2104, True),
            (2308, 2056, True),
        ]

        for idx, (pid, ppid, track) in enumerate(l):
            pt.handle_event({
                "pid": pid,
                "ppid": ppid,
                "process_name": "procname",
                "command_line": "cmdline",
                "first_seen": idx,
                "children": [],
                "track": track,
            })

        obj = pt.run()
        assert len(obj) == 3
        assert len(obj[1]["children"]) == 1
        assert len(obj[1]["children"][0]["children"]) == 2
        assert len(obj[1]["children"][0]["children"][0]["children"]) == 1
        assert len(obj[1]["children"][0]["children"][1]["children"]) == 2
        assert not obj[2]["children"]

class TestPcap(object):
    @classmethod
    def setup_class(cls):
        cls.pcap = Pcap("tests/files/pcap/mixed-traffic.pcap", {}).run()

    def test_dns_server_list(self):
        assert self.pcap["dns_servers"] == ["8.8.8.8"]

    def test_network_tls(self):
        expected = {
            "5125e361db3498ad5582861bd3e7d2833720dc2667e84898a1a9809ca5d8b026": "74df546aa33ce1cd4d4c70560c46517f4d82ff3f453bc5fada7571a11b0b40e7",
            "e06e26040000541f575837fe59fcffc048d2da914bb592947fb00d93fe3096c1": "3fc88fa50ae338e96dbadcce9d1a4a39d3ab4082bdb8486d3798b43f8de35828",
            "509c7d7cb1fbf738275005e5b8da6870ed4364334b8cc3113076094353418ef3": "a21bc2564a1317330c2896277c1a86679ace3c19ac4bb995db98543c2699b484",
            "0c2bb706845f1ffbdd2b35727671269bc1888eeb76dbfb1380bf254f66b1f304": "27f1291c893f6bdb50791667e14d54f13b49f758cdd51bfb3eef4e025c1455fa",
            "0823eb76d5fe02028d95a195e7242d4e0af2ca7d2c1e00060a3147ca51bb2fa9": "7eaecad65d025e141acf0bf63e85fc996751f2fea0a11792619d27d7116fa930",
            "042cfc85c16f9d6a357667f3fbb2424fefafce8b6e012e986ecd8f3026b8178c": "e5c7af9b9996f81c306ac0c8056d62baa20a56b0c4b44085c1b69fc49afcbab7",
            "43afb7d851b8fd110ffe10981e126c9fc698aae468ef9f824c13b5aeff0a78f7": "be044830cd9c5997982466d85e1b6653cbd7110fed56be1f326346854a216357",
            "58b9e2761e4312136d929fb08dcf83ab89547bda5f4f1a81dc78be4a511b928b": "dccc6f639bbc3f5f78df6ac3973d9f4a29d2cf4128d941182de53a546558f122",
            "58b9e2769b0988e851772e4e80a791bca639c6300e3a88765213f1c523519743": "dbba5aafa1ef148ee83a1cf8953d26a52b32e148cdd42bc24227334fa4f43fdb",
            "58b9e27681f5dcd7ab61f24cc722f8f175696e8b7558bbd519d8cde6bda9bbf1": "e73e8952daf2350fd5110cd71059eea5cb7680abbc84adb2ceeb14c81875ed4f",
            "58b9e2768f36a05b83119cce56549d8c895f58ac0d354b99fab5ba0afccfef48": "6f65a4033e33c15ae0e0380eef1647027dea3bd522c8e51f7fa81d7b7606097b",
            "58b9e276c62992aec3e2619a051f39839bf775d02937d8775e5f0585a81aff83": "86ea041b0cc229d9de9a9820a0b22fdf8f7f9c03753e974b421d67908ccc8903",
            "58b9e273319636975d4e105dab8cf3ab9f84b74620984ee99001b7da4c675ec6": "72739bf22f67f7ffab5df4050c82d43ae7b206c1d6a097de9f44b25601b28a0c",
            "58b9e273eac7840222082482b162fb812bbb53d54dfbbe6f610c3fc696863eff": "112f4ceae25c9596d88aa032fc64192711407332c7e89ae797763cf93e08bd27",
            "58b9e2735302abf0b50fea45a00c17c136413321c66614f58cd33ecaf697ed0c": "24de45a373da296fb1a80c0111d339bc4ee3859e496e971344bce56adba3feba"
        }

        found = {}
        for tls in self.pcap["tls"]:
            found[tls["server_random"]] = tls["session_id"]

        assert expected == found

    def test_network_udp(self):
        expected_src = ["192.168.56.110"]
        expected_dst = [
            "224.0.0.252", "8.8.8.8", "192.168.56.255",
            "239.255.255.250", "52.178.223.23"
        ]

        sources = []
        destinations = []

        for data in self.pcap["udp"]:
            if data["src"] not in sources:
                sources.append(data["src"])
            if data["dst"] not in destinations:
                destinations.append(data["dst"])

        assert len(self.pcap["udp"]) == 69
        assert sources == expected_src
        assert destinations == expected_dst

    def test_network_tcp(self):
        expected_src = ["192.168.56.110"]
        expected_dst = [
            "149.210.181.54",
            "178.255.83.1",
            "104.16.93.188",
            "216.58.212.202",
            "23.51.117.163",
            "23.51.123.27",
            "216.58.212.206",
            "216.58.212.195",
            "93.184.221.200",
            "204.79.197.200",
            "131.253.61.64",
            "93.184.220.20",
            "52.58.57.251",
            "40.86.224.10",
            "54.174.33.196",
            "138.91.83.37"
        ]

        sources = []
        destinations = []

        for data in self.pcap["tcp"]:
            if data["src"] not in sources:
                sources.append(data["src"])
            if data["dst"] not in destinations:
                destinations.append(data["dst"])

        assert len(self.pcap["tcp"]) == 51
        assert sources == expected_src
        assert destinations == expected_dst

    def test_network_icmp(self):
        expected_types = {0:4, 8:4}
        expected_src = ["192.168.56.110", "149.210.181.54"]
        expected_dst = ["149.210.181.54", "192.168.56.110"]
        expected_mes = ["abcdefghijklmnopqrstuvwabcdefghi"]*8

        sources = []
        destinations = []
        messages = []
        types = {}

        for data in self.pcap["icmp"]:
            if data["src"] not in sources:
                sources.append(data["src"])
            if data["dst"] not in destinations:
                destinations.append(data["dst"])
            if data["type"] in types:
                types[data["type"]] += 1
            else:
                types[data["type"]] = 1
            messages.append(data["data"])

        assert len(self.pcap["icmp"]) == 8
        assert expected_types == types
        assert expected_src == sources
        assert expected_dst == destinations
        assert expected_mes == messages

    def test_network_hosts(self):
        expected_hosts = [
            "8.8.8.8", "149.210.181.54", "178.255.83.1",
            "104.16.93.188", "216.58.212.202", "23.51.117.163",
            "23.51.123.27", "216.58.212.206", "216.58.212.195",
            "93.184.221.200", "52.178.223.23", "204.79.197.200",
            "131.253.61.64", "93.184.220.20", "52.58.57.251",
            "40.86.224.10", "54.174.33.196", "138.91.83.37",
            "55.119.32.91", "5.5.119.1"
        ]
        assert self.pcap["hosts"] == expected_hosts

    def test_network_dead_hosts(self):
        expected_dead = [
            ("55.119.32.91", 1234),
            ("5.5.119.1", 9836)
        ]

        assert self.pcap["dead_hosts"] == expected_dead

    def test_network_domains(self):
        assert len(self.pcap["domains"]) == 23

    def test_network_dns(self):
        expected_types = {
            "A": 23, "SOA": 1, "TXT": 1,
            "PTR": 3, "AAAA": 2, "CNAME": 1,
            "SRV": 1, "HINFO": 1, "NS": 1, "MX": 1
        }

        types = {}
        for res in self.pcap["dns"]:
            t = res["type"]
            if t in types:
                types[t] += 1
            else:
                types[t] = 1

        assert expected_types == types

class TestPcap2(object):
    def test_smtp_ex(self):
        pcap = Pcap2("tests/files/pcap/smtp.pcap", None, tempfile.mkdtemp())
        data = pcap.run()

        assert len(data["smtp_ex"]) == 1
        assert data["smtp_ex"][0]["req"]["username"] == "galunt"
        assert data["smtp_ex"][0]["req"]["password"] == "V1v1tr0n"
        assert data["smtp_ex"][0]["req"]["mail_to"] == ['xxxxxx.xxxx@xxxxx.com']
        assert data["smtp_ex"][0]["req"]["mail_from"] == ['xxxxxx@xxxxx.co.uk']
        assert len(data["smtp_ex"][0]["req"]["headers"]) == 10
        assert data["smtp_ex"][0]["resp"]["banner"] == "220 smtp006.mail.xxx.xxxxx.com ESMTP\r\n"

def test_parse_cmdline():
    rb = RebootReconstructor()
    assert rb.parse_cmdline("stuff.exe /Y /x -P") == (
        "stuff.exe", ["/Y", "/x", "-P"]
    )
    assert rb.parse_cmdline(u"stuff.exe \u4404\u73a8 \uecbc\uee9e") == (
        "stuff.exe", [u"\u4404\u73a8", u"\uecbc\uee9e"]
    )
