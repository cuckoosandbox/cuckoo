#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import yaml
import json
from os import path
from string import Template

def generate_probes2(definitions_path, output_path, overwrite=True):
    """ TBD """
    if not overwrite and path.isfile(output_path):
        pass
    defs  = read_definitions('apis.json')
    types = read_types('/Users/rodionovd/projects/cuckoo-osx-analyzer/analyzer/darwin/lib/core/data/types.yml')
    probes = [HEADER] + [probe_from_definition(x, types) for x in defs]
    return dump_probes(probes, output_path)
    
# FILE IO

def read_definitions(infile):
    """ TBD """
    with open(fromfile, "r") as stream:
        contents = json.load(stream)
        # Now convert the root dictionary to an array of dictionaries where
        # original keys become values for the "name" key.
        defs = []
        for key, value in contents.iteritems():
            defs.append(dict({'name': key}, **value))
        return defs
    
def read_types(infile):
    """ TBD """
    with open(infile, "r") as stream:
        return yaml.safe_load(stream)
    
def dump_probes(probes, tofile):
    """ TBD """
    with open(tofile, "w") as stream:
        stream.writelines(probes)

# GENERATION
    
def probe_from_definition(definition, types):
    """ TBD """
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
    """ TBD """
    template = Template(ENTRY_PROBE_TEMPLATE)
    mapping = {
        "__LIBRARY__": df.get("library", ""),
        "__NAME__"   : df["name"],
        "__ARGUMENTS_PUSH_ON_STACK__": push_on_stack_section(df["args"])
    }
    return template.substitute(mapping)
    
def return_probe_from_definition(df, types):
    """ TBD """
    args = df["args"]
    retval_type = df["retval_type"]
    
    template = Template(RETURN_PROBE_TEMPLATE)
    mapping = {
        "__LIBRARY__": df.get("library", ""),
        "__NAME__"   : df["name"],
        "__ARGS_FORMAT_STRING__"      : arguments_format_string(args, types),
        "__RETVAL_FORMAT_SPECIFIER__" : types[retval_type]["printf_specifier"],
        "__ARGUMENTS__"               : arguments_section(args, types),
        "__RETVAL_CAST__"             : retval_section(retval_type, types),
        "__ARGUMENTS_POP_FROM_STACK"  : pop_from_stack_section(args)
    }
    return template.substitute(mapping)
    
# -----------------------------------------------------------------------

def arguments_section(args, types):
    """ TBD """
    if len(args) == 0:
        return ""
    def serialize_arg(idx):
        serialize_argument_at_idx(idx, args, types, "self->arg%d" % idx)
    parts = [serialize_arg(i) for i in xrange(len(args))]
    return ("\n\t\t" + " ".join(parts)) 
    
def arguments_format_string(args, types):
    """ TBD """
    if len(args) == 0:
        return ""
    parts = [printf_format_string_for_type(x["argtype"], types) for x in args]
    return ", ".join(parts)
  
def retval_section(retval_type, types):
    """ TBD """
    return serialize_type(retval_type, types, "this->retval")  
    
# -------------------------------

def printf_format_string_for_type(type, all_types):
    """ TBD """
    description = type_description(type, all_types)
    if "struct" not in description:
        format = description["printf_specifier"]
    else:
        format = printf_format_string_for_struct(description, types)
    return format.replace("\"", "\\\"")

def printf_format_string_for_struct(description, types):
    fields = []
    for (name, argtype) in description["struct"].items():
        field_description = type_description(argtype, types)
        if "printf_specifier" in field_description:
            fields.append("\""+name +"\"" + " : " + field_description["printf_specifier"])
        else:
            # Yay, recursion!
            struct_format = printf_format_string_for_struct(field_description, types)
            fields.append("\""+name +"\"" + " : " + struct_format)
    return "{%s}" % ", ".join(fields)

def serialize_argument_at_idx(idx, all_args, types, accessor):
    """ TBD """
    arg = all_args[idx]
    type_name = arg["argtype"]
    if "template" in type_description(type_name, types):
        return serialize_template(type_name, types, accessor)
    else:
        return serialize_type(type_name, types, accessor)
        
def serialize_type(name, types, accessor):
    """ TBD """
    name = name.strip()
    description = type_description(name, types)
    if "struct" in description:
        # TODO(rodionovd): add support for struct arguments
        raise Exception("Not implemented yet")
    else:
        return serialize_atomic_type(name, accessor)

def serialize_atomic_type(argtype, accessor):
    """ TBD """
    # Do we need to dereference this argument and copy it to the userspace?
    if dereference_type(argtype) == argtype:
        # Nope: it's a value type
        return "(%s)(%s)," % (argtype, accessor)
    else:
        # Yep: it's a reference type
        real_type = dereference_type(argtype)
        t = (accessor, real_type, real_type, real_type, accessor, real_type)
        return "%s == (%s)NULL ? (%s)NULL : *(%s *)copyin(%s, sizeof(%s))," % t
       
def serialize_template(oftype, types, accessor=""):
    """ TBD """
    description = type_description(oftype, types)
    template = Template(description["template"])
    mapping = {"ARG" : accessor}
    # TODO(rodionovd): add support for buffers (ARG_SIZE)
    return template.substitute(mapping) + ","
    
# -------------------------------        
        
def dereference_type(type):
    """ Removes everything after the last star character in a type string,
    except for 'void *' and 'char *`. """
    if type.strip() in ["void *", "char *"]:
        return type.strip()
    try:
        return type[:type.rindex("*")].strip()
    except:
        return type.strip()
    
def type_description(name, types):
    """ TBD """
    return types[dereference_type(name)]
    
  
# -----------------------------------------------------------------------

k = [
    {"name":   "domain", "argtype": "int *"},
    {"name":     "type", "argtype": "string"},
    {"name":   "baaarr", "argtype": "void *"},
    {"name":   "asdas",  "argtype": "bar_t"},
]    

types = read_types('/Users/rodionovd/projects/cuckoo-osx-analyzer/analyzer/darwin/lib/core/data/types.yml')  

print printf_format_string_for_type("string", types)
print printf_format_string_for_type("char *", types)
print printf_format_string_for_type("float *", types)
print printf_format_string_for_type("void *", types)
print printf_format_string_for_type("pointer", types)


print "["+arguments_format_string(k, types)+"]"

# -----------------------------------------------------------------------

def push_on_stack_section(args):
    if len(args) == 0:
        return ""
    parts = ["self->deeplevel++;"]
    for idx in xrange(len(args)):
        parts.append("""self->arguments_stack[self->deeplevel, \"arg%d\"] = self->arg%d;\tself->arg%d = arg%d;""" % (idx, idx, idx, idx))
    return "\n\t".join(parts)
        

def pop_from_stack_section(args):
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
#include <stddef.h>
#pragma clang diagnostic pop
\n
"""
