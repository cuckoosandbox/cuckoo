# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class BladabindiMutexes(Signature):
    name = "bladabindi_mutexes"
    description = "Creates known Bladabindi mutexes"
    severity = 3
    categories = ["rat"]
    families = ["bladabindi"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*5cd8f17f4086744065eb0992a09e05a2",
        ".*7d31449cc24545e5baf7b7e98c5e61d9",
        ".*cf6d4ece0d2ae4e70b8976b3da569182",
        ".*bd72bdbd384fd6f5217a3e24639ac74d",
        ".*28b0d124ac25c03f8d9070a2a73a9a73",
        ".*5d571351d23508d2cc7e9aa98c23c055",
        ".*f3ef1d36b8ed15fcea19675640dc1fb9",
        ".*0a7d0e9a9cacb83cba8bd12d2a354870",
        ".*23556fb1360f366337f97c924e76ead3",
        ".*8515eb34d8f9de5af815466e9715b3e5",
        ".*7b2236d4ccefe2f5237dde10ddf4b650",
        ".*19e54ee952f699766659d1fed01ddf65",
        ".*e663d8214f143c4686f6921606a45f67",
        ".*e1476abfc54713b579a69ee33c4ddedc",
        ".*8e148bd8dd4989187be65281cdcbbefc",
        ".*b809aeeb9ddce7e022d702ffce409ffc",
        ".*279f6960ed84a752570aca7fb2dc1552",
        ".*450d7fee6062bbe1dd079a5dcbe3b195",
        ".*1a5f058929c78ffb6cadf2f9b204ab15",
        ".*b07d968a8532cdba31254eaf7d6fcbd2",
        ".*deb5514e8b36bf115118525d846a1947",
        ".*f3d0d960a86f4cceddda89606358e93d",
        ".*436524901a632dcf9c0a972738f44a6f",
        ".*8ec7d19f4f3834b8b9e2fca2371be0ff",
        ".*8e3bc91142bd8d798a10a1667ae4d2be",
        ".*47636a969bd1c6e68d83f4d0d8bc8dda",
        ".*58ba2f27f3fc1bad59483cb6206f36f2",
        ".*55f080b419cf9f54637d613ff709e342",
        ".*d5a38e9b5f206c41f8851bf04a251d26",
        ".*043ed596af7365236306a463494dc0f4",
        ".*52437699ff97396822046f0c3986db20",
        ".*53537398b429d11c09c9e346a3582f0d",
        ".*08f4dc96bbb7af09d1a37fe35c75a42f",
        ".*0b1e0da38e056c127976864a086de11e",
        ".*1ce5c21bd74c042cdcd945e699c951c5",
        ".*210519c69f3fcb1249b75dbe5267e8b6",
        ".*283660919e97cb9c040b8ccc9d65a9be",
        ".*29ed18a51dbd38c4a613ba3170db970e",
        ".*3d32b3fd8d5818ece4d448417e09241e",
        ".*45cd603ee23d7c7a771df421f5721e99",
        ".*47b88eeff7bfc9a4ac768fee084fccb6",
        ".*4a1c8e824197cd479f4b8534e5f85fc5",
        ".*5c131d3ef25b4ba634df46b4ff749912",
        ".*6ffa6c871d6a6859a95630a5da5a9bed",
        ".*773bcc010e84cda917768f4a3bb8df01",
        ".*7a8ddb5217f7b3fc0d5a82291272879e",
        ".*7d36289df0453ac60a5d14c5419a95fe",
        ".*7ec758bb61ca03c96d41aa1185ff7176",
        ".*854084595525f7929d7da906e0d2d84a",
        ".*86ef3061574874751df916be42dde289",
        ".*ba4c12bee3027d94da5c81db2d196bfd",
        ".*bfbeca4ecb787a555d9714cd849689f4",
        ".*c1e1f81975fa0ccac8c05e619f3d9f72",
        ".*c6610e18949e44ffac10d50245eda61b",
        ".*cd10b4d080df39db9b521346aa4e519e",
        ".*cd7983661d72041d386e8983e7951006",
        ".*ce8667f8b3daecf81f650f11a40ed48f",
        ".*da1559d727fe6404efa712d2c508f4e9",
        ".*dae31c02cb06222e776b9ccb9207edb1",
        ".*e09c1962cd5c0d15b904bac48faa8131",
        ".*e92a7e5d482a1ec460c8b5bf5a3013d2",
        ".*fa0e754208b9fdf88b61ad470a1ceb76",
        ".*ff70ef8c4d237338eda652592ce24d91",
        ".*602a265edf8c957bd93884df12360e22",
    ]

    files_re = [
        ".*Trojan.*exe.*tmp",
        ".*Trojan.*exe.*config",
        ".*nsy1.tmp",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            match = self.check_mutex(pattern=indicator)
            if match:
                self.mark_ioc("mutex", match)

        for indicator in self.files_re:
            match = self.check_file(pattern=indicator, regex=True)
            if match:
                self.mark_ioc("file", match)

        return self.has_marks()
