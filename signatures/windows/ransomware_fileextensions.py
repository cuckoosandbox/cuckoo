# Copyright (C) 2016 Kevin Ross, Uses code from KillerInstinct signature https://github.com/spender-sandbox/community-modified/blob/master/modules/signatures/ransomware_files.py
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

class RansomwareExtensions(Signature):
    name = "ransomware_extensions"
    description = "Appends known ransomware file extensions to files that have been encrypted"
    severity = 3
    categories = ["ransomware"]
    authors = ["Kevin Ross"]

    indicators = [
        (".*\.(?:R5A|R4A)$", ["7ev3n"]),
        (".*\.Alcatraz$", ["Alcatraz-Locker"]),
        (".*\.adk$", ["AngryDuck"]),
        (".*\.bart\.zip$", ["Bart"]),
        (".*\.(?:CHIP|DALE)$", ["CHIP"]),
        (".*\.comrade$", ["Comrade-Circle"]),
        (".*\.cry$", ["CryLocker"]),
        (".*_luck$", ["CryptoLuck"]),
        (".*\.CrySiS$", ["Crysis"]),
        (".*\.(?:id_[^\/]*\.rscl|id_[^\/]*\.scl)$", ["CryptFile2"]),
        (".*\.(?:lesli|WALLET)$", ["CryptoMix"]),
        (".*\.CRYPTOSHIELD$", ["CryptoShield"]),
        (".*\.(?:crypz|cryp1|[0-9A-F]{32}\.[0-9A-F]{5})$", ["CryptXXX"]),
        (".*\.onion$", ["Dharma"]),
        (".*\.domino$", ["Domino"]),
        (".*\.dCrypt$", ["DummyLocker"]),
        (".*dxxd$", ["DXXD"]),
        (".*\.1txt$", ["Enigma"]),
        (".*\.exotic$", ["Exotic"]),
        (".*\.fantom$", ["Fantom"]),
        (".*\.fs0ciety$", ["Fsociety"]),
        (".*\.(?:purge|globe|raid10|lovewindows)$", ["Globe"]),
        (".*\.rnsmwr$", ["Gremit"]),
        (".*\.~HL[A-Z0-9]{5}$", ["HadesLocker"]),
        (".*\.herbst$", ["Herbst"]),
        (".*\.(?:hydracrypt_ID_[a-z0-9]{8}|hydracrypttmp_ID_[a-z0-9]{8})$", ["HydraCrypt"]),
        (".*\.jaff$", ["Jaff"]),
        (".*\.(?:jaff|wlu)$", ["Jaff"]),
        (".*\.kraken$", ["Kraken"]),
        (".*\.grt$", ["Karmen"]),
        (".*\.rip$", ["KillerLocker"]),
        (".*\.k0stya$", ["Kostya"]),
        (".*\.lock93$", ["Lock93"]),
        (".*\.locklock$", ["LockLock"]),
        (".*\.(?:locky|zepto|odin|shit|thor|aesir|zzzzz|osiris)$", ["Locky"]),
        (".*\.MOLE$", ["Mole"]),
        (".*\.mordor$", ["Mordor"]),
        (".*\.(?:crypted|crypt|encrypted|encrypt|enc|locked|lock)$", ["multi-family"]),
        (".*\.(?:0x5bm|nuclear55)$", ["Nuke"]),
        (".*_nullbyte$", ["Nullbyte"]),
        (".*\.sexy$", ["PayDay"]),
        (".*\.razy$", ["Razy"]),
        (".*\.REVENGE$", ["Revenge"]),
        (".*\.sage$", ["Sage"]),
        (".*\.serpent$", ["Serpent"]),
        (".*\.toxcrypt$", ["ToxCrypt"]),
        (".*\.(?:da_vinci_code|magic_software_syndicate|no_more_ransom|Dexter)$", ["Troldesh"]),
        (".*\.Venus(f|p)$", ["VenusLocker"]),
        (".*\.(?:WNCRY|WNCRYT|WCRY)$", ["WannaCry"]),
        (".*\.wflx$", ["WildFire-Locker"]),
    ]

    def on_complete(self):
        for indicator in self.indicators:
            for filepath in self.check_file(pattern=indicator[0], regex=True, all=True):
                self.mark_ioc("file", filepath)
                if indicator[1]:
                    self.description = (
                        "Appends a known %s ransomware file extension to "
                        "files that have been encrypted" %
                        "/".join(indicator[1])
                    )

        return self.has_marks()
