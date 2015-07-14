#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import unittest

from analyzer.darwin.lib.core.packages import *

class PackagesTestCase(unittest.TestCase):

    def test_bash_package(self):
        # given
        file_type = "a bash script text executable"
        file_name = "foo.sh"
        # when
        pkg_class = choose_package_class(file_type, file_name)
        # then
        self.assertEqual(pkg_class.__name__, "Bash")

    def test_macho_package(self):
        # given
        file_type = "Mach-O 64-bit executable x86_64"
        file_name = "codesign"
        # when
        pkg_class = choose_package_class(file_type, file_name)
        # then
        self.assertEqual(pkg_class.__name__, "Macho")

    def test_macho_package_alt(self):
        # given
        file_type = "Mach-O 32-bit executable i386"
        file_name = "foobar"
        # when
        pkg_class = choose_package_class(file_type, file_name)
        # then
        self.assertEqual(pkg_class.__name__, "Macho")

    def test_zip_package(self):
        # given
        file_type = "Zip archive data, at least v1.0 to extract"
        file_name = "foobar.zip"
        # when
        pkg_class = choose_package_class(file_type, file_name)
        # then
        self.assertEqual(pkg_class.__name__, "Zip")

    def test_app_package(self):
        # given
        file_type = "directory"
        file_name = "Installer.app"
        # when
        pkg_class = choose_package_class(file_type, file_name)
        # then
        self.assertEqual(pkg_class.__name__, "App")
