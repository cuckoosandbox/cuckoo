# Copyright (C) 2012-2014 Claudio "nex" Guarnieri (@botherder)
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

class BrowserStealer(Signature):
    name = "infostealer_browser"
    description = "Steals private information from local Internet browsers"
    severity = 2
    categories = ["infostealer"]
    authors = ["nex", "Cuckoo Technologies"]
    minimum = "2.0"

    files_re = [
        ".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\\\.default\\\\signons\\.sqlite$",
        ".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\\\.default\\\\secmod\\.db$",
        ".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\\\.default\\\\cert8\\.db$",
        ".*\\\\Mozilla\\\\Firefox\\\\Profiles\\\\.*\\\\.default\\\\key3\\.db$",
        ".*\\\\(Application\\ Data|AppData).*?\\\\Google\\\\Chrome\\\\.*",
        ".*\\\\(Application\\ Data|AppData).*?\\\\Opera\\\\.*",
        ".*\\\\(Application\\ Data|AppData).*?\\\\Chromium\\\\.*",
        ".*\\\\(Application\\ Data|AppData).*?\\\\ChromePlus\\\\.*",
        ".*\\\\(Application\\ Data|AppData).*?\\\\Nichrome\\\\.*",
        ".*\\\\(Application\\ Data|AppData).*?\\\\Bromium\\\\.*",
        ".*\\\\(Application\\ Data|AppData).*?\\\\RockMelt\\\\.*",
        ".*\\\\(Application\\ Data|AppData).*?\\\\Yandex\\\\YandexBrowser\\\\.*",
    ]

    regkeys_re = [
        ".*\\\\Software\\\\Mozilla\\\\SeaMonkey",
        ".*\\\\Software\\\\Opera\\ Software",
        ".*\\\\Software\\\\Mozilla\\\\Mozilla\\ Firefox",
    ]

    def on_complete(self):
        for indicator in self.files_re:
            for filepath in self.check_file(pattern=indicator, regex=True, all=True):
                self.mark_ioc("file", filepath)

        for indicator in self.regkeys_re:
            for registry in self.check_key(pattern=indicator, regex=True, all=True):
                self.mark_ioc("registry", registry)

        return self.has_marks()
