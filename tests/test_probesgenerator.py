#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import filecmp
import unittest
from os import remove, path
from common import TESTS_DIR
from os.path import basename
from difflib import unified_diff
from analyzer.darwin.lib.dtrace.autoprobes import generate_probes
from analyzer.darwin.lib.dtrace.autoprobes import dereference_type
from analyzer.darwin.lib.dtrace.autoprobes import serialize_atomic_type
from analyzer.darwin.lib.dtrace.autoprobes import serialize_struct_type
from analyzer.darwin.lib.dtrace.autoprobes import serialize_type_with_template

DEFINITIONS_FILE = None

class ProbesGeneratorTestCase(unittest.TestCase):

    def result_file(self):
        return TESTS_DIR + "/assets/probes/" + self._testMethodName + ".d"

    def reference_file(self):
        return TESTS_DIR + "/assets/probes/" + self._testMethodName + ".d.reference"

    def tearDown(self):
        if path.isfile(self.result_file()):
            remove(self.result_file())

    def assertEmptyDiff(self, diff):
        if len(diff) > 0:
            self.fail("Diff is not empty:\n" + diff)

    # UNIT TESTS

    def test_probes_dereference_value_type(self):
        # given
        type = "scalar_t"
        # when
        output = dereference_type(type)
        # then
        self.assertEqual("scalar_t", output)

    def test_probes_dereference_reference_type(self):
        # given
        type = "foo *"
        # when
        output = dereference_type(type)
        # then
        self.assertEqual("foo", output)

    def test_probes_dereference_reference_type_with_random_spaces(self):
        # given
        type = "foo  *  "
        # when
        output = dereference_type(type)
        # then
        self.assertEqual("foo", output)

    def test_probes_dereference_types_that_must_not_be_dereferenced(self):
        # given
        type_string  = "char *"
        type_pointer = "void *"
        # when
        output_string  = dereference_type(type_string)
        output_pointer = dereference_type(type_pointer)
        # then
        self.assertEqual("char *", output_string)
        self.assertEqual("void *", output_pointer)

    def test_probes_atomic_type_serialization(self):
        # given
        type = "float"
        accessor = "self->arg0"
        # when
        output = serialize_atomic_type(type, accessor)
        # then
        self.assertEqual("(float)(self->arg0)", output)

    def test_probes_atomic_pointer_type_serialization(self):
        # given
        type = "int *"
        accessor = "self->arg0"
        # when
        output = serialize_atomic_type(type, accessor)
        # then
        self.assertEqual(
            "self->arg0 == (int)NULL ? (int)NULL : *(int *)copyin(self->arg0, sizeof(int))",
            output
        )

    def test_probes_struct_type_serialization(self):
        # given
        type = "foo_t"
        accessor = "self->arg0"
        types = {
            "float": {
                "printf_specifier": "%f",
                "native": True
            },
            "int": {
                "printf_specifier": "%f",
                "native": True
            },
            "foo_t": {
                "native": False,
                "struct": {
                    "value_f":   "float",
                    "value_int": "int *"
                }
            }
        }
        # when
        output = serialize_struct_type(type, accessor, types)
        # then
        self.assertEqual(
            "(foo_t)(self->arg0).value_int == (int)NULL ? (int)NULL : *(int *)copyin((foo_t)(self->arg0).value_int, sizeof(int)), (float)((foo_t)(self->arg0).value_f)",
            output
        )

    def test_probes_struct_pointer_type_serialization(self):
        # given
        type = "foo_t *"
        accessor = "self->arg0"
        types = {
            "float": {
                "printf_specifier": "%f",
                "native": True
            },
            "int": {
                "printf_specifier": "%f",
                "native": True
            },
            "foo_t": {
                "native": False,
                "struct": {
                    "value_f":   "float",
                    "value_int": "int *"
                }
            }
        }
        # when
        output = serialize_struct_type(type, accessor, types)
        # then
        self.assertEqual(
            "(foo_t *)(self->arg0)->value_int == (int)NULL ? (int)NULL : *(int *)copyin((foo_t *)(self->arg0)->value_int, sizeof(int)), (float)((foo_t *)(self->arg0)->value_f)",
            output
        )

    def test_probes_template_type_serialization(self):
        # given
        type = "string"
        accessor = "self->arg0"
        types = {
            "string": {
                "printf_specifier": '"%S"',
                "native": False,
                "template": '${ARG} != (int64_t)NULL ? copyinstr(${ARG}) : "<NULL>"'
            }
        }
        # when
        output = serialize_type_with_template(type, accessor, types)
        # then
        self.assertEqual(
            'self->arg0 != (int64_t)NULL ? copyinstr(self->arg0) : "<NULL>"',
            output
        )

    # INTEGRATION TESTS

    def test_probes_without_arguments_return_integer(self):
        # given
        source = [{
            "api": "foo",
            "args": [
                {"name": "key", "argtype": "void *"},
                {"name": "hash", "argtype": "uint64_t"},
                {"name": "rando", "argtype": "foo_t *"}
            ],
            "retval_type": "int",
            "category" : "foobar",
            "library" : "libfoo"
        }]
        destination = self.result_file()
        # when
        generate_probes(source, destination)
        # then
        self.assertEmptyDiff(file_diff(self.reference_file(), destination))

def file_diff(a, b):
    with open(a, 'r') as astream, open(b, 'r') as bstream:
        return "".join(unified_diff(
            astream.readlines(),
            bstream.readlines(),
            basename(a), basename(b),
            n=0
        ))
