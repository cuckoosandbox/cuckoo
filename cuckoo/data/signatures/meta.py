# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

class SignatureMeta(object):
    bundles = {
        'document': ['doc', 'ppt', 'xsl'],
        'executable': ['exe'],
        'browser': ['js', 'url']
    }

    @staticmethod
    def context_from_package(package):
        for context, packages in SignatureMeta.bundles.iteritems():
            if package in packages:
                return context

        return None
