# Copyright (C) 2012 Claudio "nex" Guarnieri (@botherder)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature

class FTPStealer(Signature):
    name = "infostealer_ftp"
    description = "Harvests credentials from local FTP client softwares"
    severity = 3
    categories = ["infostealer"]
    authors = ["nex", "RedSocks", "Cuckoo Technologies"]
    minimum = "2.0"

    files_re = [
        ".*\\\\CuteFTP\\\\sm\\.dat$",
        ".*\\\\CuteFTP\\ Lite\\\\sm\\.dat$",
        ".*\\\\CuteFTP\\ Pro\\\\sm\\.dat$",
        ".*\\\\FlashFXP\\\\.*\\\\(Sites|Quick|History)\\.dat$",
        ".*\\\\VanDyke\\\\Config\\\\Sessions.*",
        ".*\\\\FTP Explorer\\\\",
        ".*\\\\LeechFTP\\\\",
        ".*\\\\SmartFTP\\\\",
        ".*\\\\TurboFTP\\\\",
        ".*\\\\FTPRush\\\\",
        ".*\\\\LeapFTP\\\\",
        ".*\\\\FTPGetter\\\\",
        ".*\\\\ALFTP\\\\",
        ".*\\\\Ipswitch\\\\WS_FTP.*",
        ".*\\\\wcx_ftp\\.ini$",
        ".*\\\\32BitFtp\\.ini$",
        ".*\\\\CoffeeCup\\ Software\\\\SharedSettings.*(sqlite|ccs)$",
        ".*\\\\ExpanDrive\\\\drives\\.js$",
        ".*\\\\FileZilla\\\\(sitemanager|recentservers|filezilla)\\.xml$",
    ]

    regkeys_re = [
        ".*\\\\Software\\\\Far.*\\\\Hosts$",
        ".*\\\\Software\\\\Far.*\\\\FTPHost$",
        ".*\\\\Software\\\\Far.*?\\\\FTP\\\\Hosts$",
        ".*\\\\Software\\\\TurboFTP\\\\",
        ".*\\\\Software\\\\Robo-FTP.*\\\\FTPServers$",
        ".*\\\\Software\\\\Ghisler\\\\Windows Commander$",
        ".*\\\\Software\\\\Ghisler\\\\Total Commander$",
        ".*\\\\Software\\\\BPFTP\\\\",
        ".*\\\\Software\\\\BulletProof Software\\\\BulletProof FTP Client\\\\",
        ".*\\\\Software\\\\BPFTP\\\\Bullet\\ Proof\\ FTP",
        ".*\\\\Software\\\\FTP\\ Explorer\\\\Profiles",
        ".*\\\\CuteFTP\\ .\\ Professional\\\\QCToolbar",
        ".*\\\\Software\\\\VanDyke\\\\SecureFX",
        ".*\\\\Software\\\\South\\ River\\ Technologies\\\\WebDrive",
        ".*\\\\Software\\\\LinasFTP",
        ".*\\\\Software\\\\SoftX\\.org\\\\FTPClient",
        ".*\\\\Software\\\\Sota\\\\FFFTP",
        ".*\\\\Software\\\\LeechFTP",
        ".*\\\\Software\\\\CoffeeCup\\ Software",
        ".*\\\\Software\\\\FlashFXP",
        ".*\\\\Software\\\\FTP\\ Explorer\\\\FTP\\ Explorer",
        ".*\\\\Software\\\\FlashPeak\\\\BlazeFtp",
        ".*\\\\Software\\\\LeapWare",
        ".*\\\\Software\\\\SimonTatham\\\\PuTTY",
        ".*\\\\Software\\\\Cryer\\\\WebSitePublisher",
        ".*\\\\Software\\\\ExpanDrive",
        ".*\\\\Software\\\\Martin\\ Prikryl",
        ".*\\\\Software\\\\AceBIT",
        ".*\\\\Software\\\\Nico\\ Mak\\ Computing\\\\WinZip",
        ".*\\\\Software\\\\FTPWare\\\\CoreFTP",
    ]

    def on_complete(self):
        for indicator in self.files_re:
            for filepath in self.check_file(pattern=indicator, regex=True, all=True):
                self.mark_ioc("file", filepath)

        for indicator in self.regkeys_re:
            for registry in self.check_key(pattern=indicator, regex=True, all=True):
                self.mark_ioc("registry", registry)

        return self.has_marks()
