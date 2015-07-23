#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import filecmp
import unittest

from common import TESTS_DIR
from analyzer.darwin.lib.dtrace.autoprobes import generate_probes

DEFINITIONS_FILE = None

class ProbesGeneratorTestCase(unittest.TestCase):

    # HELPERS

    def definitions_file(self):
        return TESTS_DIR + "/assets/" + self._testMethodName + ".json"

    def result_file(self):
        return TESTS_DIR + "/assets/" + self._testMethodName + ".d"

    def reference_file(self):
        return TESTS_DIR + "/assets/" + self._testMethodName + ".d.reference"

    # TESTS

    def test_probes_without_arguments_return_integer(self):
        # given
        source = self.definitions_file()
        destination = self.result_file()
        # when
        generate_probes(source, destination)
        # then
        self.assertTrue(
            _files_are_equal(self.result_file(), self.reference_file())
        )

    def test_probes_without_arguments_return_string(self):
        # given
        source = self.definitions_file()
        destination = self.result_file()
        # when
        generate_probes(source, destination)
        # then
        self.assertTrue(
            _files_are_equal(self.result_file(), self.reference_file())
        )

    def test_probes_without_arguments_return_pointer(self):
        # given
        source = self.definitions_file()
        destination = self.result_file()
        # when
        generate_probes(source, destination)
        # then
        self.assertTrue(
            _files_are_equal(self.result_file(), self.reference_file())
        )

    def test_probes_one_argument_integer_return_integer(self):
        # given
        source = self.definitions_file()
        destination = self.result_file()
        # when
        generate_probes(source, destination)
        # then
        self.assertTrue(
            _files_are_equal(self.result_file(), self.reference_file())
        )

    def test_probes_one_argument_integer_return_string(self):
        # given
        source = self.definitions_file()
        destination = self.result_file()
        # when
        generate_probes(source, destination)
        # then
        self.assertTrue(
            _files_are_equal(self.result_file(), self.reference_file())
        )

    def test_probes_one_argument_integer_return_float(self):
        # given
        source = self.definitions_file()
        destination = self.result_file()
        # when
        generate_probes(source, destination)
        # then
        self.assertTrue(
            _files_are_equal(self.result_file(), self.reference_file())
        )

    def test_probes_one_argument_integer_return_double(self):
        # given
        source = self.definitions_file()
        destination = self.result_file()
        # when
        generate_probes(source, destination)
        # then
        self.assertTrue(
            _files_are_equal(self.result_file(), self.reference_file())
        )

    def test_probes_one_argument_string_return_integer(self):
        # given
        source = self.definitions_file()
        destination = self.result_file()
        # when
        generate_probes(source, destination)
        # then
        self.assertTrue(
            _files_are_equal(self.result_file(), self.reference_file())
        )

    def test_probes_one_argument_float_return_integer(self):
        # given
        source = self.definitions_file()
        destination = self.result_file()
        # when
        generate_probes(source, destination)
        # then
        self.assertTrue(
            _files_are_equal(self.result_file(), self.reference_file())
        )

    def test_probes_one_argument_float_return_float(self):
        # given
        source = self.definitions_file()
        destination = self.result_file()
        # when
        generate_probes(source, destination)
        # then
        self.assertTrue(
            _files_are_equal(self.result_file(), self.reference_file())
        )

    def test_probes_one_argument_float_return_pointer(self):
        # given
        source = self.definitions_file()
        destination = self.result_file()
        # when
        generate_probes(source, destination)
        # then
        self.assertTrue(
            _files_are_equal(self.result_file(), self.reference_file())
        )

    def test_probes_one_argument_double_return_integer(self):
        # given
        source = self.definitions_file()
        destination = self.result_file()
        # when
        generate_probes(source, destination)
        # then
        self.assertTrue(
            _files_are_equal(self.result_file(), self.reference_file())
        )

    def test_probes_two_arguments_integer_string_return_integer(self):
        # given
        source = self.definitions_file()
        destination = self.result_file()
        # when
        generate_probes(source, destination)
        # then
        self.assertTrue(
            _files_are_equal(self.result_file(), self.reference_file())
        )

    def test_probes_two_arguments_integer_string_return_pointer(self):
        # given
        source = self.definitions_file()
        destination = self.result_file()
        # when
        generate_probes(source, destination)
        # then
        self.assertTrue(
            _files_are_equal(self.result_file(), self.reference_file())
        )

    def test_probes_two_arguments_float_string_return_double(self):
        # given
        source = self.definitions_file()
        destination = self.result_file()
        # when
        generate_probes(source, destination)
        # then
        self.assertTrue(
            _files_are_equal(self.result_file(), self.reference_file())
        )

    def test_probes_two_arguments_float_integer_return_string(self):
        # given
        source = self.definitions_file()
        destination = self.result_file()
        # when
        generate_probes(source, destination)
        # then
        self.assertTrue(
            _files_are_equal(self.result_file(), self.reference_file())
        )

def _files_are_equal(a, b):
    return filecmp.cmp(a, b)
