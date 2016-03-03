# Copyright (C) 2010-2015 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class BadCerts(Signature):
    name = "bad_certificate"
    description = "Contains known-bad certificates"
    severity = 2

    sha1_sigs = {
        # Buhtrap
        "cf5a43d14c6ad0c7fdbcbe632ab7c789e39443ee": "http://www.welivesecurity.com/2015/04/09/operation-buhtrap/",
        "e9af1f9af597a9330c52a7686bf70b0094ad7616": "http://www.welivesecurity.com/2015/04/09/operation-buhtrap/",
        "3e1a6e52a1756017dd8f03ff85ec353273b20c66": "http://www.welivesecurity.com/2015/04/09/operation-buhtrap/",
        "efad94fc87b2b3a652f1a98901204ea8fbeef474": "http://www.welivesecurity.com/2015/04/09/operation-buhtrap/",

        # Stolen Sony cert
        "8df46b5fdac2eb3b4757f99866c199ff2b13427a": "https://www.virustotal.com/en/file/4c2efe2f1253b94f16a1cab032f36c7883e4f6c8d9fc17d0ee553b5afb16330c/analysis/",

        # Stolen Bit9 cert
        "555d2d20851e849f0c109e243cf8a5da1f9995d7": "https://blog.bit9.com/2013/02/25/bit9-security-incident-update/",

        # Sysprint AG cert used in Turla
        "24215864f128972b2622172dee6282460799ca46": "https://www.virustotal.com/en/file/4eba5182826becfc842315a0ce85f9e03aada8cc73d1e54ed0b55754ab89d9e0/analysis/",

        # Stolen Source Medical Solutions cert
        "b501aab2ffc3bddb7e847c4acee4be41de38f16e": "https://www.virustotal.com/en/file/05d5123fd0c38e7166c98c564dd8d46defe96926b5e116276499407bf558bbe5/analysis/",

        # Adobe stolen cert
        "fdf01dd3f37c66ac4c779d92623c77814a07fe4c": "https://www.adobe.com/support/security/advisories/apsa12-01.html",

        # Used in a Dridex sample: KASHTAN OOO
        "401909e89a0e59335b624e147719f0b88d51705a": "https://www.virustotal.com/en/file/ffc1f577b754a897bd88fdb67801ea3f87a2bc858700f36dd71e3b67bf0d262d/analysis/1431946975/",

        # Used in a Punkey sample: MOGLIANI & SON LIMITED
        "c5d386f697777643751ec33b6b689eef71791293": "https://www.virustotal.com/en/file/6d78550d140061607557bac7c9ba70787e9589b200758f4ab8d59f6504bb7563/analysis/",

        # Used in Duqu2: HON HAI PRECISION INDUSTRY CO. LTD.
        "c7938dd4bec741574683b4f3dd54717f98e54c90": "https://www.virustotal.com/en/file/bc4ae56434b45818f57724f4cd19354a13e5964fd097d1933a30e2e31c9bdfa5/analysis/",

        # HackingTeam Dump
        "2e8734348c03390d24faf96e86bb01b39e3ad4db": "https://otx.alienvault.com/indicator/file/851bc793f0716dae783fae420a1e530238d7663a8c7ca9469e4581e8792ee0bb/",
        "b7c646e3a433986e165ba45b209da4a2c4111939": "https://www.virustotal.com/en/file/d54733ac06eced264e5e8ae679081519d599cf1057088d2fbe0645ff08c753b8/analysis/",
        "fdc9281ab92d4fb85a03254dcb62d1c29a803fb1": "https://www.virustotal.com/en/file/58ec76ce82da7a63acecaf36858029fd6966fe1d079ed99389a23d088d7bb315/analysis/",
        "2a1da6dc8635e6c725cccbe6c035eec813fbeb2e": "https://www.virustotal.com/en/file/88a38001fff99c3d33e8ba7acf20b2908948200ea77a62f86b9c0726c1a1c0aa/analysis/",

        # Wild Neutron (Stolen Acer Incorporated cert)
        "0d859141ee9a0c6e725ffe6bcfc99f3efcc3fc07": "https://www.virustotal.com/en/analisis//file/8969bcc5072499a2acfeff583bc7849ba25629eb0cbb708d581fc8d58388e772/analysis/",

        # Used in Dridex, BIZNES AVTOMATYKA
        "9a9c618cc8f50e9ffb24b6cc8b34858fa65e778c": "https://www.virustotal.com/en/file/4d2568d0d2babc7299827db3b3807a824b2965fe1cd3c938eaf7ed57d93c0421/analysis/1438908495/",

        # Flame
        "1d190facf06e133e8754e564c76c17da8f566fbb": "https://www.f-secure.com/weblog/archives/00002377.html",
        "03166d5bc0edf8f514790c76d23703e803281a92": "https://www.f-secure.com/weblog/archives/00002377.html",
        "58aedc5058e505d381e63de54186ff23b490c3b3": "https://www.f-secure.com/weblog/archives/00002377.html",
        "2a83e9020591a55fc6ddad3fb102794c52b24e70": "https://www.f-secure.com/weblog/archives/00002377.html",

        # Techsnab
        "2feef9b548981d861c6a347243cc70c0b1102604": "https://www.virustotal.com/en/file/218db0851bd8aa548b30bdf2d75e1fce44c99ee1ea910b904e938a9e39c20526/analysis/",

        # BrowseFox / NetFilter
        "d8f6f0216a552e83080dfefd98ddd652e09e704c": "https://www.virustotal.com/en/file/ad5101cb617b7fda7a952271eb7655fc38360b04782967ce44703ac5ebf51e52/analysis/",

        # eDellRoot
        "98a04e4163357790c4a79e6d713ff0af51fe6927": "http://www.theregister.co.uk/2015/11/23/dude_youre_getting_pwned/",
    }

    cn_sigs = {
        # SearchProtect
        "ClientConnect LTD": "https://www.virustotal.com/en/file/d59e36eee768b21281e4d5654134e089fe0a1079b209793504f318ace729f214/analysis/",
    }

    def on_complete(self):
        for sig in self.get_results("static", {}).get("signature", []):
            if sig["sha1"] in self.sha1_sigs:
                self.mark(cert=sig, reference=self.sha1_sigs[sig["sha1"]])
            elif sig["common_name"] in self.cn_sigs:
                self.mark(cert=sig, reference=self.cn_sigs[sig["common_name"]])

        return self.has_marks()
