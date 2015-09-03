#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import filecmp
import unittest
from os import remove, path
from common import TESTS_DIR
from difflib import unified_diff
from subprocess import check_call

from analyzer.darwin.lib.dtrace.autoprobes import generate_probes
from analyzer.darwin.lib.dtrace.autoprobes import dereference_type
from analyzer.darwin.lib.dtrace.autoprobes import serialize_atomic_type
from analyzer.darwin.lib.dtrace.autoprobes import serialize_struct_type
from analyzer.darwin.lib.dtrace.autoprobes import serialize_type_with_template

SIGNATURES_FILE = path.join(TESTS_DIR, "..", "analyzer", "darwin", "lib",
                            "core", "data", "signatures.yml")

class ProbesGeneratorTestCase(unittest.TestCase):

    def result_file(self):
        return path.join(TESTS_DIR, "assets", "probes", self._testMethodName + ".d")

    def reference_file(self):
        return path.join(TESTS_DIR, "assets", "probes", self._testMethodName + ".d.reference")

    def tearDown(self):
        if path.isfile(self.result_file()):
            remove(self.result_file())

    def assertEmptyDiff(self, diff):
        if len(diff) > 0:
            self.fail("Diff is not empty:\n" + diff)

    def assertDtraceCompiles(self, script_file):
        # Define the required stuff (see apicalls.d)
        decl = """self int64_t arguments_stack[unsigned long, string];self deeplevel;dtrace:::BEGIN{self->deeplevel = 0;self->arg0  = (int64_t)0;self->arg1  = (int64_t)0;self->arg2  = (int64_t)0;self->arg3  = (int64_t)0;self->arg4  = (int64_t)0;self->arg5  = (int64_t)0;self->arg6  = (int64_t)0;self->arg7  = (int64_t)0;self->arg8  = (int64_t)0;self->arg9  = (int64_t)0;self->arg10 = (int64_t)0;self->arg11 = (int64_t)0;}"""
        with open(script_file, "r+") as outfile:
            contents = outfile.read()
            outfile.seek(0, 0)
            outfile.write(decl + "\n" + contents)
        check_call(["sudo", "dtrace", "-e", "-C", "-s", script_file, "-c", "date"])

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
        type = "foo      *  "
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
        output = serialize_atomic_type(type, type, accessor)
        # then
        self.assertEqual("(float)(self->arg0)", output)

    def test_probes_atomic_pointer_type_serialization(self):
        # given
        type = "int *"
        accessor = "self->arg0"
        # when
        output = serialize_atomic_type(type, "int", accessor)
        # then
        self.assertEqual(
            "!!(self->arg0) ? (int)0 : *(int *)copyin((uint64_t)self->arg0, sizeof(int))",
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
            "char *": {
                "printf_specifier": '"%S"',
                "native": True,
                "template":
                    '!!(${ARG}) ? copyinstr((uint64_t)${ARG}) : "<NULL>"'
            },
            "foo_t": {
                "native": False,
                "struct": {
                    "value_f":   "float",
                    "value_str": "char *"
                }
            }
        }
        # when
        output = serialize_struct_type(type, accessor, types)
        # then
        self.assertEqual(
            '(float)(((foo_t)(self->arg0)).value_f), !!(((foo_t)(self->arg0)).value_str) ? copyinstr((uint64_t)((foo_t)(self->arg0)).value_str) : "<NULL>"',
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
            "!!(((foo_t *)(self->arg0))->value_int) ? (int)0 : *(int *)copyin((uint64_t)((foo_t *)(self->arg0))->value_int, sizeof(int)), (float)(((foo_t *)(self->arg0))->value_f)",
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
                "template": '!!(${ARG}) ? copyinstr((uint64_t)${ARG}) : "<NULL>"'
            }
        }
        # when
        output = serialize_type_with_template(type, accessor, types)
        # then
        self.assertEqual(
            '!!(self->arg0) ? copyinstr((uint64_t)self->arg0) : "<NULL>"',
            output
        )

    def test_probes_integration(self):
        # given
        source = [{
            "api": "system",
            "is_success_condition": "retval == 0",
            "args": [
                {"name": "command", "type": "char *"}
            ],
            "retval_type": "int",
            "category": "foobar"
        },
        {
            "api": "socket",
            "is_success_condition": "retval > 0",
            "args": [
                {"name": "domain",   "type": "int"},
                {"name": "type",     "type": "double"},
                {"name": "protocol", "type": "test_t *"}
            ],
            "retval_type": "size_t",
            "category": "network"
        }]
        destination = self.result_file()
        # when
        generate_probes(source, destination)
        # then
        self.assertEmptyDiff(file_diff(self.reference_file(), destination))
        self.assertDtraceCompiles(destination)

def file_diff(a, b):
    with open(a, 'r') as astream, open(b, 'r') as bstream:
        return "".join(unified_diff(
            astream.readlines(),
            bstream.readlines(),
            path.basename(a), path.basename(b),
            n=0
        ))
