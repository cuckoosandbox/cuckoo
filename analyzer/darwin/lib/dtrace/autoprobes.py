#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import logging
from os import path
from json import load
from string import Template

LOG = logging.getLogger(__name__)

def generate_probes(source, output_path, overwrite=False):
    """ Generates dtrace pid-based probes at $output_path based definitions
    from $source JSON file.

    By default if there's already a file at $output_path, this function is no-op.
    To overwrite the destination file, set $overwrite to True.
    """
    if not overwrite and path.isfile(output_path):
        return # we already have our probes generated
    defs = _read_definitions(source)
    probes = [HEADER] + [_create_probe(x) for x in defs]
    _save_probes(probes, output_path)

# File IO
def _read_definitions(fromfile):
    """ Reads API definitions from the given JSON file.
    See lib/core/data/apis.json for the reference.
    """
    try:
        with open(fromfile, "r") as infile:
            contents = load(infile)
            # Now convert the root dictionary to an array of dictionaries where
            # original keys become values for the "name" key.
            defs = []
            for key, value in contents.iteritems():
                defs.append(dict({'name': key}, **value))
            return defs
    except IOError:
        LOG.exception("Could not open apis.json file")
    except ValueError:
        LOG.exception("apis.json contains invalid JSON")

def _save_probes(probes, tofile):
    try:
        with open(tofile, "w") as outfile:
            outfile.writelines(probes)
    except IOError:
        LOG.exception("Could not open output file for writing")
#
# Generation
#
def _create_probe(definition):
    if definition.get("__ignore__", False):
        return ""
    elif len(definition["args"]) == 0:
        # We only need entry probes to save arguments. If there're no arguments,
        # don't even bother creating an empty probe.
        return _create_return_probe(definition)
    else:
        return _create_entry_probe(definition) + _create_return_probe(definition)

#
# Generation detals
#
def _create_entry_probe(definition):
    template = Template(ENTRY_PROBE_TEMPLATE)
    mapping = {
        "__LIBRARY__": definition.get("library", ""),
        "__NAME__"   : definition["name"],
        "__ARGUMENTS_PUSH_ON_STACK__": _push_on_stack_section(definition["args"])
    }
    return template.substitute(mapping)

def _create_return_probe(definition):
    args = definition["args"]
    retval_type = definition["retval_type"]
    template = Template(RETURN_PROBE_TEMPLATE)
    mapping = {
        "__LIBRARY__": definition.get("library", ""),
        "__NAME__"   : definition["name"],
        "__ARGS_FORMAT_STRING__"      : _args_format_string(args),
        "__RETVAL_FORMAT_SPECIFIER__" : PRINTF_FORMATS[retval_type],
        "__ARGUMENTS__"               : _arguments_section(args),
        "__RETVAL_CAST__"             : _c_cast_for_type(retval_type),
        "__ARGUMENTS_POP_FROM_STACK"  : _pop_from_stack_section(args)
    }
    return template.substitute(mapping)

def _push_on_stack_section(args):
    parts = []
    for idx in xrange(len(args)):
        parts.append("""self->arguments_stack[self->deeplevel, \"arg%d\"] = self->arg%d;
\tself->arg%d = arg%d;""" % (idx, idx, idx, idx))
    if len(parts) == 0:
        return ""
    else:
        parts.insert(0, "self->deeplevel++;")
        return "\n\t".join(parts)


def _pop_from_stack_section(args):
    parts = []
    for idx in xrange(len(args)):
        parts.append("""self->arg%d = self->arguments_stack[self->deeplevel, \"arg%d\"];
\tself->arguments_stack[self->deeplevel, \"arg%d\"] = 0;""" % (idx, idx, idx))
    if len(parts) == 0:
        return ""
    else:
        parts.append("--self->deeplevel;")
        return "\n\t" + "\n\t".join(parts)


def _args_format_string(args):
    c_format_of = lambda x: _format_specifier_from_type(x["type"])
    return ", ".join([c_format_of(x) for x in args])


def _arguments_section(args):
    parts = []
    for idx, item in enumerate(args):
        if item["type"] == "string":
            # dtrace strings need to be copied into userland with copyinstr() first,
            # so we use this function instead of casting. Also, verify that the
            # pointer is valid before dereferencing
            parts.append("self->arg%d != NULL ? copyinstr(self->arg%d) : \"<NULL>\"," % (idx, idx))
        elif item["type"] == "buffer":
            # Use copyin() and stringof() for retriving an arbitatry buffer; thus
            # we need to know a place to look for it's size
            if "size_arg" not in item:
                raise Exception("Missing `size_arg` key for buffer argument \"%s\"" % item["name"])
            size_arg_name = item["size_arg"]
            size_arg_idx = [i for i, x in enumerate(args) if x["name"] == size_arg_name][0]
            #
            cmd = "stringof(copyin(self->arg%d, self->arg%d))" % (idx, size_arg_idx)
            parts.append("self->arg%d != NULL ? %s : \"<NULL>\"," % (idx, cmd))
        else:
            parts.append("%s(self->arg%d)," % (_c_cast_for_type(item["type"]), idx))
    return ("\n\t\t" + " ".join(parts)) if len(parts) > 0 else ""


def _format_specifier_from_type(type_string):
    if type_string in PRINTF_FORMATS:
        return PRINTF_FORMATS[type_string]
    else:
        raise Exception("Unsupported type string: \"%s\"" % type_string)

def _c_cast_for_type(type_string):
    if type_string in C_CASTS:
        return C_CASTS[type_string]
    else:
        return "(%s)" % type_string

# Constants
PRINTF_FORMATS = {
    "pointer" : "%llu",
    # %S is for raw string: ignore special characters, etc. Must be escaped.
    "string"  : "\\\"%S\\\"",
    # %S will print everything, not just ASCII, so we use it for buffers too
    "buffer"  : "\\\"%S\\\"",
    "integer" : "%d",
    "float"   : "%f",
    "double"  : "%lf",
    "char"    : "\\\"%c\\\"",
    "uint8_t" : "%u",
    "uint16_t": "%u",
    "uint32_t": "%u",
    "uint64_t": "%llu",
    "int64_t" : "%lld",
    "int32_t" : "%d",
    "int16_t" : "%d",
    "int8_t"  : "%d"
}

C_CASTS = {
    "pointer" : "(unsigned long long)",
    # dtrace strings need to be copied into userland with copyinstr() first,
    # so we use this function instead of casting
    "string"  : "copyinstr",
    "integer" : "(int)",
    "float"   : "(float)",
    "double"  : "(double)",
    "char"    : "(char)"
}
# Templates
ENTRY_PROBE_TEMPLATE = """pid$$target:${__LIBRARY__}:${__NAME__}:entry
{
\t${__ARGUMENTS_PUSH_ON_STACK__}
}\n"""

RETURN_PROBE_TEMPLATE = """pid$$target:${__LIBRARY__}:${__NAME__}:return
{
\tthis->retval = arg1;
\tthis->timestamp_ms = walltimestamp/1000000;
\tprintf("{\\\"api\\\":\\\"%s\\\", \\\"args\\\":[${__ARGS_FORMAT_STRING__}], \\\"retval\\\":${__RETVAL_FORMAT_SPECIFIER__}, \\\"timestamp\\\":%lld, \\\"pid\\\":%d, \\\"ppid\\\":%d, \\\"tid\\":%d, \\\"errno\\\":%d}\\n",
\t\tprobefunc,${__ARGUMENTS__}
\t\t${__RETVAL_CAST__}(this->retval),
\t\t(int64_t)this->timestamp_ms, pid, ppid, tid, errno);${__ARGUMENTS_POP_FROM_STACK}
}\n"""

HEADER = """/* For some reason either dtrace or clang preprocessor refuses to identify standard
 * C integer types like int64_t or uint8_t. Thus we must include stdint.h with the
 * following patches.
 */
/* (1) fix sys/_types/_int8_t.h */
#define __signed signed
/* (2) cdefs.h throws "Unsupported compiler detected" warning, ignore it */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-W#warnings"
#include <stdint.h>
#pragma clang diagnostic pop
\n
"""
