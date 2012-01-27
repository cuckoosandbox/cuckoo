# Cuckoo Sandbox - Automated Malware Analysis
# Copyright (C) 2010-2012  Claudio "nex" Guarnieri (nex@cuckoobox.org)
# http://www.cuckoobox.org
#
# This file is part of Cuckoo.
#
# Cuckoo is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Cuckoo is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/.

import os
import sys
import magic
import string

import cuckoo.processing.pefile as pefile
import cuckoo.processing.peutils as peutils

# Partially taken from http://malwarecookbook.googlecode.com/svn/trunk/3/8/pescanner.py

class PortableExecutable:
    def __init__(self, file_path):
        self.file_path = file_path
        self.pe = None

    def _convert_char(self, char):
        if char in string.ascii_letters or \
           char in string.digits or \
           char in string.punctuation or \
           char in string.whitespace:
            return char
        else:
            return r'\x%02x' % ord(char)

    def _convert_to_printable(self, s):
        return ''.join([self._convert_char(c) for c in s])

    def _get_filetype(self, data):
        ms = magic.open(magic.MAGIC_NONE)
        ms.load()
        return ms.buffer(data)

    def _get_peid_signatures(self):
        if not self.pe:
            return None

        try:
            signatures = peutils.SignatureDatabase("cuckoo/processing/UserDB.TXT")
            return signatures.match(self.pe, ep_only = True)
        except:
            return None

    def _get_imported_symbols(self):
        if not self.pe:
            return None

        imports = []

        if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    symbols = []
                    for imported_symbol in entry.imports:
                        symbol = {}
                        symbol["address"] = hex(imported_symbol.address)
                        symbol["name"] = imported_symbol.name
                        symbols.append(symbol)

                    imports_section = {}
                    imports_section["dll"] = entry.dll
                    imports_section["imports"] = symbols
                    imports.append(imports_section)
                except:
                    continue

        return imports
    
    def _get_exported_symbols(self):
        if not self.pe:
            return None
        
        exports = []
        
        if hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            for exported_symbol in self.pe.DIRECTORY_ENTRY_EXPORT:
                symbol = {}
                symbol["address"] = hex(self.pe.OPTIONAL_HEADER.ImageBase + exported_symbol.address)
                symbol["name"] = exported_symbol.name
                symbol["ordinal"] = exported_symbol.ordinal
                exports.append(symbol)

        return exports

    def _get_sections(self):
        if not self.pe:
            return None

        sections = []

        for entry in self.pe.sections:
            try:
                section = {}
                section["name"] = self._convert_to_printable(entry.Name.strip())
                section["virtual_address"] = hex(entry.VirtualAddress)
                section["virtual_size"] = hex(entry.Misc_VirtualSize)
                section["size_of_data"] = hex(entry.SizeOfRawData)
                section["entropy"] = entry.get_entropy()
                sections.append(section)
            except:
                continue

        return sections

    def _get_resources(self):
        if not self.pe:
            return None

        resources = []

        if hasattr(self.pe, "DIRECTORY_ENTRY_RESOURCE"):
            for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                try:
                    resource = {}

                    if resource_type.name is not None:
                        name = "%s" % resource_type.name
                    else:
                        name = "%s" % pefile.RESOURCE_TYPE.get(resource_type.struct.Id)
                    if name == None:
                        name = "%d" % resource_type.struct.Id

                    if hasattr(resource_type, "directory"):
                        for resource_id in resource_type.directory.entries:
                            if hasattr(resource_id, "directory"):
                                for resource_lang in resource_id.directory.entries:
                                    data = self.pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                    filetype = self._get_filetype(data)
                                    language = pefile.LANG.get(resource_lang.data.lang, None)
                                    sublanguage = pefile.get_sublang_name_for_lang(resource_lang.data.lang, resource_lang.data.sublang)

                                    resource["name"] = name
                                    resource["offset"] = ("%-8s" % hex(resource_lang.data.struct.OffsetToData)).strip()
                                    resource["size"] = ("%-8s" % hex(resource_lang.data.struct.Size)).strip()
                                    resource["filetype"] = filetype
                                    resource["language"] = language
                                    resource["sublanguage"] = sublanguage
                                    resources.append(resource)
                except:
                    continue

        return resources

    def _get_versioninfo(self):
        if not self.pe:
            return None

        infos = []
        if hasattr(self.pe, "VS_VERSIONINFO"):
            if hasattr(self.pe, "FileInfo"):
                for entry in self.pe.FileInfo:
                    try:
                        if hasattr(entry, "StringTable"):
                            for st_entry in entry.StringTable:
                                for str_entry in st_entry.entries.items():
                                    entry = {}
                                    entry["name"] = self._convert_to_printable(str_entry[0])
                                    entry["value"] = self._convert_to_printable(str_entry[1])
                                    infos.append(entry)
                        elif hasattr(entry, "Var"):
                            for var_entry in entry.Var:
                                if hasattr(var_entry, "entry"):
                                    entry = {}
                                    entry["name"] = self._convert_to_printable(var_entry.entry.keys()[0])
                                    entry["value"] = self._convert_to_printable(var_entry.entry.values()[0])
                                    infos.append(entry)
                    except:
                        continue

        return infos

    def process(self):
        if not os.path.exists(self.file_path):
            return None

        try:
            self.pe = pefile.PE(self.file_path)
        except pefile.PEFormatError, why:
            return None

        results = {}
        results["peid_signatures"] = self._get_peid_signatures()
        results["pe_imports"] = self._get_imported_symbols()
        results["pe_exports"] = self._get_exported_symbols()
        results["pe_sections"] = self._get_sections()
        results["pe_resources"] = self._get_resources()
        results["pe_versioninfo"] = self._get_versioninfo()

        return results
