# Copyright (C) 2015 Kevin Ross, Optiv, Inc. (brad.spengler@optiv.com), Updated 2016 for cuckoo 2.0
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class BitcoinWallet(Signature):
    name = "infostealer_bitcoin"
    description = "Attempts to access Bitcoin/ALTCoin wallets"
    severity = 3
    categories = ["infostealer"]
    authors = ["Kevin Ross", "Optiv"]
    minimum = "2.0"

    file_indicators = [
         ".*\\\\wallet\.dat$",
         ".*\\\\Bitcoin\\\\.*",
         ".*\\\\Electrum\\\\.*",
         ".*\\\\MultiBit\\\\.*",
         ".*\\\\Litecoin\\\\.*",
         ".*\\\\Namecoin\\\\.*",
         ".*\\\\Terracoin\\\\.*",
         ".*\\\\PPCoin\\\\.*",
         ".*\\\\Primecoin\\\\.*",
         ".*\\\\Feathercoin\\\\.*",
         ".*\\\\Novacoin\\\\.*",
         ".*\\\\Freicoin\\\\.*",
         ".*\\\\Devcoin\\\\.*",
         ".*\\\\Franko\\\\.*",
         ".*\\\\ProtoShares\\\\.*",
         ".*\\\\Megacoin\\\\.*",
         ".*\\\\Quarkcoin\\\\.*",
         ".*\\\\Worldcoin\\\\.*",
         ".*\\\\Infinitecoin\\\\.*",
         ".*\\\\Ixcoin\\\\.*",
         ".*\\\\Anoncoin\\\\.*",
         ".*\\\\BBQcoin\\\\.*",
         ".*\\\\Digitalcoin\\\\.*",
         ".*\\\\Mincoin\\\\.*",
         ".*\\\\GoldCoin\\ \(GLD\)\\\\.*",
         ".*\\\\Yacoin\\\\.*",
         ".*\\\\Zetacoin\\\\.*",
         ".*\\\\Fastcoin\\\\.*",
         ".*\\\\I0coin\\\\.*",
         ".*\\\\Tagcoin\\\\.*",
         ".*\\\\Bytecoin\\\\.*",
         ".*\\\\Florincoin\\\\.*",
         ".*\\\\Phoenixcoin\\\\.*",
         ".*\\\\Luckycoin\\\\.*",
         ".*\\\\Craftcoin\\\\.*",
         ".*\\\\Junkcoin\\\\.*",
    ]

    def on_complete(self):
        for indicator in self.file_indicators:
            for match in self.check_file(pattern=indicator, regex=True, all=True):
                self.mark_ioc("file", match)

        return self.has_marks()
