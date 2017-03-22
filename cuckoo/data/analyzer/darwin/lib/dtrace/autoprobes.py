#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import yaml
from os import path
from string import Template
from sets import Set

def generate_probes(definitions, output_path, overwrite=True):
    """ TBD """
    if not overwrite and path.isfile(output_path):
        pass
    if isinstance(definitions, list):
        defs = definitions
    else:
        defs = read_definitions(definitions)
    types = read_types(path.abspath(path.join(__file__, "../../core/data/types.yml")))
    contents  = [HEADER] + typedefs_for_custom_structs(defs, types)
    contents += [probe_from_definition(x, types) for x in defs]
    dump_probes(contents, output_path)

# FILE IO

def read_definitions(fromfile):
    """ Read API signatures from a file. """
    with open(fromfile, "r") as stream:
        contents = yaml.safe_load(stream)
        # Now convert the root dictionary to an array of dictionaries where
        # original keys become values for the "api" key.
        # FIXME(rodionovd): yes, I know, it should be an array..
        return [dict({'api': k}, **v) for k, v in contents.iteritems()]

def read_types(infile):
    """ Reads types definitions from a file. """
    with open(infile, "r") as stream:
        return yaml.safe_load(stream)

def dump_probes(probes, tofile):
    """ Writes the given list of dtrace probes to a file. If the file
    already exists, it's truncated."""
    with open(tofile, "w") as stream:
        stream.writelines(probes)

# GENERATION

def probe_from_definition(definition, types):
    """ Maps the given API definition to an actual dtrace probe(s). """
    if definition.get('__ignore__', False):
        return ""
    # We only need entry probes to save arguments
    elif len(definition['args']) == 0:
        return return_probe_from_definition(definition, types)
    else:
        entry_probe  = entry_probe_from_definition(definition)
        return_probe = return_probe_from_definition(definition, types)
        return entry_probe + return_probe

def entry_probe_from_definition(df):
    """ Generates an entry dtrace probe from the given API definition. """
    template = Template(ENTRY_PROBE_TEMPLATE)
    mapping = {
        "__LIBRARY__": df.get("library", ""),
        "__NAME__"   : df["api"],
        "__ARGUMENTS_PUSH_ON_STACK__": push_on_stack_section(df["args"])
    }
    return template.substitute(mapping)

def return_probe_from_definition(df, types):
    """ Generates a return dtrace probe from the given API definition. """
    args = df["args"]
    retval_type = df["retval_type"]
    printf_specifier = type_description(retval_type, types)["printf_specifier"]

    template = Template(RETURN_PROBE_TEMPLATE)
    mapping = {
        "__LIBRARY__": df.get("library", ""),
        "__NAME__"   : df["api"],
        "__ARGS_FORMAT_STRING__"      : arguments_format_string(args, types),
        "__RETVAL_FORMAT_SPECIFIER__" : printf_specifier,
        "__ARGUMENTS__"               : arguments_section(args, types),
        "__RETVAL__"                  : retval_section(retval_type, types),
        "__ARGUMENTS_POP_FROM_STACK__": pop_from_stack_section(args)
    }
    return template.substitute(mapping)

def typedefs_for_custom_structs(defs, types):
    """ Returns a list of typedef statements for custom structures
    defined in `types.yml`."""
    def flatten(list_of_lists):
        return sum(list_of_lists, [])
    def deep_search_types(parent, types):
        result = Set()
        for t in parent:
            description = type_description(t, types)
            if "struct" in description:
                result |= deep_search_types(description["struct"].values(), types)
            result.add(dereference_type(t))
        return result
    # We will only generate typedefs for struct that are actually in use
    obviously_used_types = [x["type"] for x in flatten([y["args"] for y in defs])]
    all_used_types = deep_search_types(obviously_used_types, types)

    struct_types = {
        k:v for (k, v) in types.iteritems() if "struct" in v and k in all_used_types
    }
    typedefs = []
    for (name, description) in struct_types.iteritems():
        fields = []
        for (f,t) in description["struct"].iteritems():
            fields.append("%s %s;" % (t, f))
        template = "typedef struct {\n\t%s\n} %s;\n\n"
        typedefs.append(template % ("\n\t".join(fields), name))
    return typedefs

# -----------------------------------------------------------------------

def arguments_section(args, types):
    """ Returns a serialization statement for accessing values of
    the given arguments. """
    if len(args) == 0:
        return ""
    def serialize_arg(idx):
        return serialize_argument_at_idx(idx, args, "self->arg%d" % idx, types)
    parts = [serialize_arg(i) for i in xrange(len(args))]
    return ("\n\t\t" + ", ".join(parts) + ",")

def arguments_format_string(args, types):
    """ Returns a format string for printing the given arguments
    with printf(). """
    if len(args) == 0:
        return ""
    parts = [printf_format_for_type(x["type"], types) for x in args]
    return ", ".join(parts)

def retval_section(retval_type, types):
    """ Returns a serialization stetement for a return value of
    the given type. """
    return serialize_type(retval_type, "this->retval", types)

# -------------------------------

def printf_format_for_type(t, types):
    """ Returns a format string for printing the given type
    (either atomic or struct). """
    description = type_description(t, types)
    if "struct" in description:
        specifer = printf_format_for_struct(t, types)
    else:
        specifer = description["printf_specifier"]
    return specifer.replace("\"", "\\\"")

def printf_format_for_struct(t, types):
    """ Returns a format string for printing the given struct type. """
    fields = []
    for (name, argtype) in type_description(t, types)["struct"].items():
        printf_specifier = type_description(argtype, types).get("printf_specifier", None)
        if printf_specifier != None:
            fields.append("\""+name +"\"" + " : " + printf_specifier)
        else:
            # Yay, recursion!
            struct_format = printf_format_for_struct(argtype, types)
            fields.append("\""+name +"\"" + " : " + struct_format)
    return "{%s}" % ", ".join(fields)

def serialize_argument_at_idx(idx, all_args, accessor, types):
    """ For an argument at the given index, returns a serialization
    statement for it's value. """
    type_name = all_args[idx]["type"]
    return serialize_type(type_name, accessor, types)

def serialize_type(name, accessor, types):
    """ Returns a serialization statement for the given type. """
    name = name.strip()
    description = type_description(name, types)
    if "struct" in description:
        return serialize_struct_type(name, accessor, types)
    elif "template" in description:
        return serialize_type_with_template(name, accessor, types)
    else:
        cast = description.get("cast", dereference_type(name))
        return serialize_atomic_type(name, cast, accessor)

def serialize_atomic_type(argtype, cast, accessor):
    """ Returns a serialization statement for the given atomic type.
    In case of pointers, values they're referencing will be used instead
    (see `dereference_type()` for exceptions). """
    # Do we need to dereference this argument and copy it to the userspace?
    if dereference_type(argtype) == argtype:
        # Nope: it's a value type
        return "(%s)(%s)" % (cast, accessor)
    else:
        # Yep: it's a reference type
        real_type = dereference_type(argtype)
        t = (accessor, cast, real_type, accessor, real_type)
        return "!!(%s) ? (%s)0 : *(%s *)copyin((uint64_t)%s, sizeof(%s))" % t

def serialize_struct_type(struct_type, accessor, types):
    """ Returns a serialization statement for the given structure type. """
    fields = []
    if struct_type == dereference_type(struct_type):
        memeber_operator = "."
    else:
        memeber_operator = "->"
    structure = type_description(struct_type, types)["struct"]
    for (field_name, field_type) in structure.iteritems():
        fields.append(serialize_type(
            field_type,
            "((%s)(%s))" % (struct_type, accessor) + memeber_operator + field_name,
            types
        ))
    return ", ".join(fields)

def serialize_type_with_template(oftype, accessor, types):
    """ Returns a serialization template for the given type
    with all placeholders replaced with the actual values. """
    template = Template(type_description(oftype, types)["template"])
    mapping = {"ARG" : accessor}
    # TODO(rodionovd): add support for buffers (ARG_SIZE)
    return template.substitute(mapping)

# -------------------------------

def dereference_type(t):
    """ Removes everything after the last star character in a type string,
    except for 'void *' and 'char *`. """
    if t.strip() in ["void *", "char *"]:
        return t.strip()
    try:
        return t[:t.rindex("*")].strip()
    except:
        return t.strip()

def type_description(name, types):
    """ Returns a dictionary description the given type. See `types.yml`
    for more information about keys and values there. """
    return types[dereference_type(name)]

# -----------------------------------------------------------------------

def push_on_stack_section(args):
    """ Composes a "push arguments on stack" section of
    an entry PID dtrace probe. """
    if len(args) == 0:
        return ""
    parts = ["self->deeplevel++;"]
    for idx in xrange(len(args)):
        parts.append(
            """self->arguments_stack[self->deeplevel, \"arg%d\"] = self->arg%d;\n\tself->arg%d = arg%d;""" % (idx, idx, idx, idx)
        )
    return "\n\t".join(parts)


def pop_from_stack_section(args):
    """ Composes a "pop arguments from stack" section of
    a return PID dtrace probe. """
    if len(args) == 0:
        return ""
    parts = []
    for idx in xrange(len(args)):
        parts.append("""self->arg%d = self->arguments_stack[self->deeplevel, \"arg%d\"];
\tself->arguments_stack[self->deeplevel, \"arg%d\"] = 0;""" % (idx, idx, idx))
    parts.append("--self->deeplevel;")
    return "\n\t" + "\n\t".join(parts)


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
\t\t${__RETVAL__},
\t\t(int64_t)this->timestamp_ms, pid, ppid, tid, errno);${__ARGUMENTS_POP_FROM_STACK__}
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
#include <stddef.h>
#pragma clang diagnostic pop
\n
"""
