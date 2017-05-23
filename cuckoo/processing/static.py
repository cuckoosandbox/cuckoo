# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import bs4
import ctypes
import datetime
import logging
import oletools.olevba
import os
import peepdf.JSAnalysis
import peepdf.PDFCore
import pefile
import peutils
import re
import struct
import zipfile

try:
    import M2Crypto
    HAVE_MCRYPTO = True
except ImportError:
    HAVE_MCRYPTO = False

try:
    import PyV8
    HAVE_PYV8 = True

    PyV8  # Fake usage.
except:
    HAVE_PYV8 = False

try:
    from elftools.common.exceptions import ELFError
    from elftools.common.py3compat import (
            ifilter, byte2int, bytes2str, itervalues, str2bytes)
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection, DynamicSegment
    from elftools.elf.enums import ENUM_D_TAG
    from elftools.elf.segments import InterpSegment, NoteSegment
    from elftools.elf.sections import SymbolTableSection
    from elftools.elf.gnuversions import (
        GNUVerSymSection, GNUVerDefSection,
        GNUVerNeedSection,
        )
    from elftools.elf.relocation import RelocationSection
    from elftools.elf.descriptions import (
        describe_ei_class, describe_ei_data, describe_ei_version,
        describe_ei_osabi, describe_e_type, describe_e_machine,
        describe_e_version_numeric, describe_p_type, describe_p_flags,
        describe_sh_type, describe_sh_flags,
        describe_symbol_type, describe_symbol_bind, describe_symbol_visibility,
        describe_symbol_shndx, describe_reloc_type, describe_dyn_tag,
        describe_ver_flags, describe_note
        )
    from elftools.elf.constants import E_FLAGS
    from elftools.dwarf.dwarfinfo import DWARFInfo
    from elftools.dwarf.descriptions import (
        describe_reg_name, describe_attr_value, set_global_machine_arch,
        describe_CFI_instructions, describe_CFI_register_rule,
        describe_CFI_CFA_rule,
        )
    from elftools.dwarf.constants import (
        DW_LNS_copy, DW_LNS_set_file, DW_LNE_define_file)
    from elftools.dwarf.callframe import CIE, FDE
    HAS_ELFTOOLS = True
except ImportError:
     HAS_ELFTOOLS = False

from cuckoo.common.abstracts import Processing
from cuckoo.common.objects import Archive, File
from cuckoo.common.utils import convert_to_printable, to_unicode, jsbeautify
from cuckoo.compat import magic
from cuckoo.misc import cwd, dispatch, Structure

log = logging.getLogger(__name__)

# Partially taken from
# http://malwarecookbook.googlecode.com/svn/trunk/3/8/pescanner.py

class PortableExecutable(object):
    """PE analysis."""

    def __init__(self, file_path):
        """@param file_path: file path."""
        self.file_path = file_path
        self.pe = None

    def _get_filetype(self, data):
        """Gets filetype, uses libmagic if available.
        @param data: data to be analyzed.
        @return: file type or None.
        """
        return magic.from_buffer(data)

    def _get_peid_signatures(self):
        """Gets PEID signatures.
        @return: matched signatures or None.
        """
        try:
            sig_path = cwd("peutils", "UserDB.TXT", private=True)
            signatures = peutils.SignatureDatabase(sig_path)
            return signatures.match(self.pe, ep_only=True)
        except:
            return None

    def _get_imported_symbols(self):
        """Gets imported symbols.
        @return: imported symbols dict or None.
        """
        imports = []

        for entry in getattr(self.pe, "DIRECTORY_ENTRY_IMPORT", []):
            try:
                symbols = []
                for imported_symbol in entry.imports:
                    symbols.append({
                        "address": hex(imported_symbol.address),
                        "name": imported_symbol.name,
                    })

                imports.append({
                    "dll": convert_to_printable(entry.dll),
                    "imports": symbols,
                })
            except:
                log.exception("Unable to parse imported symbols.")

        return imports

    def _get_exported_symbols(self):
        """Gets exported symbols.
        @return: exported symbols dict or None.
        """
        exports = []

        if hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            for exported_symbol in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exports.append({
                    "address": hex(self.pe.OPTIONAL_HEADER.ImageBase +
                                   exported_symbol.address),
                    "name": exported_symbol.name,
                    "ordinal": exported_symbol.ordinal,
                })

        return exports

    def _get_sections(self):
        """Gets sections.
        @return: sections dict or None.
        """
        sections = []

        for entry in self.pe.sections:
            try:
                section = {}
                section["name"] = convert_to_printable(entry.Name.strip("\x00"))
                section["virtual_address"] = "0x{0:08x}".format(entry.VirtualAddress)
                section["virtual_size"] = "0x{0:08x}".format(entry.Misc_VirtualSize)
                section["size_of_data"] = "0x{0:08x}".format(entry.SizeOfRawData)
                section["entropy"] = entry.get_entropy()
                sections.append(section)
            except:
                continue

        return sections

    def _get_resources(self):
        """Get resources.
        @return: resources dict or None.
        """
        resources = []

        if hasattr(self.pe, "DIRECTORY_ENTRY_RESOURCE"):
            for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                try:
                    resource = {}

                    if resource_type.name is not None:
                        name = str(resource_type.name)
                    else:
                        name = str(pefile.RESOURCE_TYPE.get(resource_type.struct.Id))

                    if hasattr(resource_type, "directory"):
                        for resource_id in resource_type.directory.entries:
                            if hasattr(resource_id, "directory"):
                                for resource_lang in resource_id.directory.entries:
                                    data = self.pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                    filetype = self._get_filetype(data)
                                    language = pefile.LANG.get(resource_lang.data.lang, None)
                                    sublanguage = pefile.get_sublang_name_for_lang(resource_lang.data.lang, resource_lang.data.sublang)

                                    resource["name"] = name
                                    resource["offset"] = "0x{0:08x}".format(resource_lang.data.struct.OffsetToData)
                                    resource["size"] = "0x{0:08x}".format(resource_lang.data.struct.Size)
                                    resource["filetype"] = filetype
                                    resource["language"] = language
                                    resource["sublanguage"] = sublanguage
                                    resources.append(resource)
                except:
                    continue

        return resources

    def _get_versioninfo(self):
        """Get version info.
        @return: info dict or None.
        """
        infos = []
        if hasattr(self.pe, "VS_VERSIONINFO"):
            if hasattr(self.pe, "FileInfo"):
                for entry in self.pe.FileInfo:
                    try:
                        if hasattr(entry, "StringTable"):
                            for st_entry in entry.StringTable:
                                for str_entry in st_entry.entries.items():
                                    entry = {}
                                    entry["name"] = convert_to_printable(str_entry[0])
                                    entry["value"] = convert_to_printable(str_entry[1])
                                    infos.append(entry)
                        elif hasattr(entry, "Var"):
                            for var_entry in entry.Var:
                                if hasattr(var_entry, "entry"):
                                    entry = {}
                                    entry["name"] = convert_to_printable(var_entry.entry.keys()[0])
                                    entry["value"] = convert_to_printable(var_entry.entry.values()[0])
                                    infos.append(entry)
                    except:
                        continue

        return infos

    def _get_imphash(self):
        """Gets imphash.
        @return: imphash string or None.
        """
        try:
            return self.pe.get_imphash()
        except AttributeError:
            return None

    def _get_timestamp(self):
        """Get compilation timestamp.
        @return: timestamp or None.
        """
        try:
            pe_timestamp = self.pe.FILE_HEADER.TimeDateStamp
        except AttributeError:
            return None

        dt = datetime.datetime.fromtimestamp(pe_timestamp)
        return dt.strftime("%Y-%m-%d %H:%M:%S")

    def _get_pdb_path(self):
        """Get the path to any available debugging symbols."""
        try:
            for entry in getattr(self.pe, "DIRECTORY_ENTRY_DEBUG", []):
                raw_offset = entry.struct.PointerToRawData
                size_data = entry.struct.SizeOfData
                debug_data = self.pe.__data__[raw_offset:raw_offset+size_data]

                if debug_data.startswith("RSDS"):
                    return debug_data[24:].strip("\x00").decode("latin-1")
        except:
            log.exception("Exception parsing PDB path")

    def _get_signature(self):
        """If this executable is signed, get its signature(s)."""
        dir_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        if len(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY) < dir_index:
            return []

        dir_entry = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[dir_index]
        if not dir_entry or not dir_entry.VirtualAddress or not dir_entry.Size:
            return []

        if not HAVE_MCRYPTO:
            log.critical(
                "You do not have the m2crypto library installed preventing "
                "certificate extraction. Please read the Cuckoo "
                "documentation on installing m2crypto (you need SWIG "
                "installed and then `pip install m2crypto==0.24.0`)!"
            )
            return []

        signatures = self.pe.write()[dir_entry.VirtualAddress+8:]
        bio = M2Crypto.BIO.MemoryBuffer(signatures)
        if not bio:
            return []

        pkcs7_obj = M2Crypto.m2.pkcs7_read_bio_der(bio.bio_ptr())
        if not pkcs7_obj:
            return []

        ret = []
        p7 = M2Crypto.SMIME.PKCS7(pkcs7_obj)
        for cert in p7.get0_signers(M2Crypto.X509.X509_Stack()) or []:
            subject = cert.get_subject()
            ret.append({
                "serial_number": "%032x" % cert.get_serial_number(),
                "common_name": subject.CN,
                "country": subject.C,
                "locality": subject.L,
                "organization": subject.O,
                "email": subject.Email,
                "sha1": "%040x" % int(cert.get_fingerprint("sha1"), 16),
                "md5": "%032x" % int(cert.get_fingerprint("md5"), 16),
            })

            if subject.GN and subject.SN:
                ret[-1]["full_name"] = "%s %s" % (subject.GN, subject.SN)
            elif subject.GN:
                ret[-1]["full_name"] = subject.GN
            elif subject.SN:
                ret[-1]["full_name"] = subject.SN

        return ret

    def run(self):
        """Run analysis.
        @return: analysis results dict or None.
        """
        if not os.path.exists(self.file_path):
            return {}

        try:
            self.pe = pefile.PE(self.file_path)
        except pefile.PEFormatError:
            return {}

        results = {}
        results["peid_signatures"] = self._get_peid_signatures()
        results["pe_imports"] = self._get_imported_symbols()
        results["pe_exports"] = self._get_exported_symbols()
        results["pe_sections"] = self._get_sections()
        results["pe_resources"] = self._get_resources()
        results["pe_versioninfo"] = self._get_versioninfo()
        results["pe_imphash"] = self._get_imphash()
        results["pe_timestamp"] = self._get_timestamp()
        results["pdb_path"] = self._get_pdb_path()
        results["signature"] = self._get_signature()
        results["imported_dll_count"] = len([x for x in results["pe_imports"] if x.get("dll")])
        return results

# Addapted from
# https://github.com/eliben/pyelftools/blob/master/scripts/readelf.py
class ReadElf(object):
    """ display_* methods are used to emit output into the output stream
    """
    def __init__(self, file):
        """ file:
                stream object with the ELF file to read
        """
        self.elffile = ELFFile(file)

        # Lazily initialized if a debug dump is requested
        self._dwarfinfo = None
        self._versioninfo = None

    def display_file_header(self):
        """ Display the ELF file header
        """
        block_str = dict()
        header = self.elffile.header
        e_ident = header['e_ident']
        block_str.setdefault("magic", str(' '.join('%2.2x' % byte2int(b) for b in self.elffile.e_ident_raw)))
        block_str.setdefault("class", describe_ei_class(e_ident['EI_CLASS']))
        block_str.setdefault("data", describe_ei_data(e_ident['EI_DATA']))
        block_str.setdefault("ei_version", describe_ei_version(e_ident['EI_VERSION']))
        block_str.setdefault("os_abi", describe_ei_osabi(e_ident['EI_OSABI']))
        block_str.setdefault("abi_version", e_ident['EI_ABIVERSION'])
        block_str.setdefault("type", describe_e_type(header['e_type']))
        block_str.setdefault("machine", describe_e_machine(header['e_machine']))
        block_str.setdefault("version", describe_e_version_numeric(header['e_version']))
        block_str.setdefault("entry_point_address" ,self._format_hex(header['e_entry']))
        block_str.setdefault("start_of_program_headers", header['e_phoff'])
        #block_str.setdefault(' (bytes into file)\n')
        block_str.setdefault("start_of_section_headers", header['e_shoff'])
        #block_str.setdefault(' (bytes into file)')
        block_str.setdefault("flags", "{}{}".format(
            self._format_hex(header['e_flags']),
            self.decode_flags(header['e_flags'])
        ))
        block_str.setdefault("size_of_this_header", header['e_ehsize'])
        block_str.setdefault("size_of_program_headers", header['e_phentsize'])
        block_str.setdefault("number_of_program_headers", header['e_phnum'])
        block_str.setdefault("size_of_section_headers", header['e_shentsize'])
        block_str.setdefault("number_of_section_headers", header['e_shnum'])
        block_str.setdefault("section_header_string_table_index",header['e_shstrndx'])

        return block_str

    def decode_flags(self, flags):
        description = ""
        if self.elffile['e_machine'] == "EM_ARM":
            if flags & E_FLAGS.EF_ARM_HASENTRY:
                description += ", has entry point"

            version = flags & E_FLAGS.EF_ARM_EABIMASK
            if version == E_FLAGS.EF_ARM_EABI_VER5:
                description += ", Version5 EABI"
        elif self.elffile['e_machine'] == "EM_MIPS":
            if flags & E_FLAGS.EF_MIPS_NOREORDER:
                description += ", noreorder"
            if flags & E_FLAGS.EF_MIPS_CPIC:
                description += ", cpic"
            if not (flags & E_FLAGS.EF_MIPS_ABI2) and not (flags & E_FLAGS.EF_MIPS_ABI_ON32):
                description += ", o32"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_1:
                description += ", mips1"

        return description

    def display_program_headers(self, show_heading=True):
        """ Display the ELF program headers.
            If show_heading is True, displays the heading for this information
            (Elf file type is...)
        """
        program_headers = list()
        if self.elffile.num_segments() == 0:
            #program_headers += 'There are no program headers in this file.'
            return program_headers

        elfheader = self.elffile.header
        if show_heading:
            program_headers.setdefault("elf_file_type_is", describe_e_type(elfheader['e_type']))
            program_headers.setdefault("entry_point_is", self._format_hex(elfheader['e_entry']))
            # readelf weirness - why isn't e_phoff printed as hex? (for section
            # headers, it is...)
            #'There are %s program headers, starting at offset', elfheader['e_phnum'], elfheader['e_phoff']


        # Now comes the table of program headers with their attributes. Note
        # that due to different formatting constraints of 32-bit and 64-bit
        # addresses, there are some conditions on elfclass here.
        #
        # First comes the table heading
        #
        """
        if self.elffile.elfclass == 32:
            program_headers += '  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align\n'
        else:
            program_headers += '  Type           Offset             VirtAddr           PhysAddr\n'
            program_headers += '                 FileSiz            MemSiz              Flags  Align\n'
        """

        # Now the entries
        #
        for segment in self.elffile.iter_segments():
           # program_headers += str('  %-14s \s' % describe_p_type(segment['p_type']))
            tmp_dict = dict()

            tmp_dict.setdefault("type", "%-14s \s" % describe_p_type(segment['p_type']))

            if self.elffile.elfclass == 32:
                tmp_dict.setdefault("p_vaddr", self._format_hex(segment['p_paddr'], fullhex=True))
                tmp_dict.setdefault("p_paddr", self._format_hex(segment['p_paddr'], fullhex=True))
                tmp_dict.setdefault("offset", self._format_hex(segment['p_offset'], fieldsize=6))
                """
                program_headers += '%s %s %s %s %s %-3s %s\n' % (
                    self._format_hex(segment['p_offset'], fieldsize=6),
                    self._format_hex(segment['p_vaddr'], fullhex=True),
                    self._format_hex(segment['p_paddr'], fullhex=True),
                    self._format_hex(segment['p_filesz'], fieldsize=5),
                    self._format_hex(segment['p_memsz'], fieldsize=5),
                    describe_p_flags(segment['p_flags']),
                    self._format_hex(segment['p_align']))
                """
            else: # 64
                tmp_dict.setdefault("p_vaddr", self._format_hex(segment['p_offset'], fullhex=True))
                tmp_dict.setdefault("p_paddr", self._format_hex(segment['p_paddr'], fullhex=True))
                tmp_dict.setdefault("offset", self._format_hex(segment['p_offset'], fullhex=True))
                """
                program_headers += '%s %s %s' % (
                    self._format_hex(segment['p_offset'], fullhex=True),
                    self._format_hex(segment['p_vaddr'], fullhex=True),
                    self._format_hex(segment['p_paddr'], fullhex=True))
                program_headers += '                 %s %s  %-3s    %s\n' % (
                    self._format_hex(segment['p_filesz'], fullhex=True),
                    self._format_hex(segment['p_memsz'], fullhex=True),
                    describe_p_flags(segment['p_flags']),
                    # lead0x set to False for p_align, to mimic readelf.
                    # No idea why the difference from 32-bit mode :-|
                    self._format_hex(segment['p_align'], lead0x=False))
                """

            program_headers.append(tmp_dict)
        # Sections to segments mapping
        #
        """
        if self.elffile.num_sections() == 0:
            # No sections? We're done
            return program_headers

        program_headers += '\n Section to Segment mapping:\n'
        program_headers += '  Segment Sections...\n'

        for nseg, segment in enumerate(self.elffile.iter_segments()):
            program_headers += str('   %2.2d     \n' % nseg)

            for section in self.elffile.iter_sections():
                if (    not section.is_null() and
                        segment.section_in_segment(section)):
                    program_headers += str('%s \n' % section.name)

            program_headers += "\n"
        """
        return program_headers

    def display_section_headers(self, show_heading=True):
        """ Display the ELF section headers
        """
        section_header = list()
        elfheader = self.elffile.header
        """
        if show_heading:
            section_header.append( 'There are %s section headers, starting at offset %s\n' % (
                elfheader['e_shnum'], self._format_hex(elfheader['e_shoff']))
        """
        #section_header.append('\nSection Header%s:\n' % (
        #    's' if elfheader['e_shnum'] > 1 else ''))

        # Different formatting constraints of 32-bit and 64-bit addresses
        """
        if self.elffile.elfclass == 32:
            section_header.append('  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al\n')
        else:
            section_header.append('  [Nr] Name              Type             Address           Offset\n')
            section_header.append('       Size              EntSize          Flags  Link  Info  Align')
        """
        # Now the entries
        section_header = list()

        for nsec, section in enumerate(self.elffile.iter_sections()):
            tmp_dict = dict()

            tmp_dict.setdefault("name", "%-17.17s" % section.name)
            tmp_dict.setdefault("type", "%-15.15s" % describe_sh_type(section['sh_type']))

            if self.elffile.elfclass == 32:
                tmp_dict.setdefault("addr", self._format_hex(section['sh_addr'], fieldsize=8, lead0x=False))
                tmp_dict.setdefault("offset", self._format_hex(section['sh_offset'], fieldsize=6, lead0x=False))
                """
                #section_header.append(('%s %s %s %s %3s %2s %3s %2s\n' % (
                    self._format_hex(section['sh_addr'], fieldsize=8, lead0x=False),
                    self._format_hex(section['sh_offset'], fieldsize=6, lead0x=False),
                    self._format_hex(section['sh_size'], fieldsize=6, lead0x=False),
                    self._format_hex(section['sh_entsize'], fieldsize=2, lead0x=False),
                    describe_sh_flags(section['sh_flags']),
                    section['sh_link'], section['sh_info'],
                    section['sh_addralign'])))
                """
            else: # 64
                """
                section_header.append( ' %s  %s\n' % (
                    self._format_hex(section['sh_addr'], fullhex=True, lead0x=False),
                    self._format_hex(section['sh_offset'],
                        fieldsize=16 if section['sh_offset'] > 0xffffffff else 8,
                        lead0x=False)))
                section_header.append( '       %s  %s %3s      %2s   %3s     %s\n' % (
                    self._format_hex(section['sh_size'], fullhex=True, lead0x=False),
                    self._format_hex(section['sh_entsize'], fullhex=True, lead0x=False),
                    #describe_sh_flags(section['sh_flags']),
                    #section['sh_link'], section['sh_info'],
                    #section['sh_addralign'])
                )
                """
                tmp_dict.setdefault("addr", self._format_hex(section['sh_addr'], fieldsize=8, lead0x=False))
                tmp_dict.setdefault("offset", self._format_hex(section['sh_offset'], fieldsize=6, lead0x=False))
            section_header.append(tmp_dict)
        """
        section_header.append( 'Key to Flags:\n')
        section_header.append( '  W (write), A (alloc), X (execute), M (merge), S (strings)\n')
        if self.elffile['e_machine'] in ('EM_X86_64', 'EM_L10M'):
            section_header.append( ', l (large)\n')
        else:
            section_header.append( "\n")
        section_header.append( '  I (info), L (link order), G (group), T (TLS), E (exclude), x (unknown)\n')
        section_header.append( '  O (extra OS processing required) o (OS specific), p (processor specific)\n')
        """
        return section_header

    def display_symbol_tables(self):
        """ Display the symbol tables contained in the file
        """
        symbol_tables = list()
        self._init_versioninfo()

        for section in self.elffile.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            tmp_dict = dict()
            if section['sh_entsize'] == 0:
                #symbol_tables +="\nSymbol table '%s' has a sh_entsize of zero!\n" % (
                #     section.name)
                continue

            #symbol_tables +="\nSymbol table '%s' contains %s entries:\n" % (
            #    section.name, section.num_symbols())
            tmp_dict["name"] = section.name
            """
            if self.elffile.elfclass == 32:
                symbol_tables +='   Num:    Value  Size Type    Bind   Vis      Ndx Name'
            else: # 64
                symbol_tables +='   Num:    Value          Size Type    Bind   Vis      Ndx Name'
            """
            for nsym, symbol in enumerate(section.iter_symbols()):
                version_info = ''
                # readelf doesn't display version info for Solaris versioning
                if (section['sh_type'] == 'SHT_DYNSYM' and
                        self._versioninfo['type'] == 'GNU'):
                    version = self._symbol_version(nsym)
                    if (version['name'] != symbol.name and
                        version['index'] not in ('VER_NDX_LOCAL',
                                                 'VER_NDX_GLOBAL')):
                        if version['filename']:
                            # external symbol
                            version_info = '@%(name)s (%(index)i)' % version
                        else:
                            # internal symbol
                            if version['hidden']:
                                version_info = '@%(name)s' % version
                            else:
                                version_info = '@@%(name)s' % version

                tmp_dict["num"] = nsym
                tmp_dict["value"] = self._format_hex(symbol['st_value'], fullhex=True, lead0x=False)
                tmp_dict["size"] = symbol['st_size']
                tmp_dict["type"] = describe_symbol_type(symbol['st_info']['type'])
                tmp_dict["bind"] = describe_symbol_bind(symbol['st_info']['bind'])
                tmp_dict["vis"] = describe_symbol_visibility(symbol['st_other']['visibility'])
                tmp_dict["ndx_name"] = symbol.name
                tmp_dict["version"] = version_info
                if tmp_dict not in symbol_tables:
                    symbol_tables.append(tmp_dict)
                """
                # symbol names are truncated to 25 chars, similarly to readelf
                symbol_tables +='%6d: %s %5d %-7s %-6s %-7s %4s %.25s%s\n' % (
                    nsym,
                    self._format_hex(
                        symbol['st_value'], fullhex=True, lead0x=False),
                    symbol['st_size'],
                    describe_symbol_type(symbol['st_info']['type']),
                    describe_symbol_bind(symbol['st_info']['bind']),
                    describe_symbol_visibility(symbol['st_other']['visibility']),
                    describe_symbol_shndx(symbol['st_shndx']),
                    symbol.name,
                    version_info)
            """
            return symbol_tables

    def display_dynamic_tags(self):
        """ Display the dynamic tags contained in the file
        """
        dynamic_tags = list()
        for section in self.elffile.iter_sections():
            tmp_dict = dict()
            if not isinstance(section, DynamicSection):
                continue
            #dynamic_tags += "\nDynamic section at offset %s contains %s entries:\n" % (
            #    self._format_hex(section['sh_offset']),
            #    section.num_tags())
            #dynamic_tags += "  Tag        Type                         Name/Value\n"
            for tag in section.iter_tags():
                if tag.entry.d_tag == 'DT_NEEDED':
                    parsed = 'Shared library: [%s]' % tag.needed
                elif tag.entry.d_tag == 'DT_RPATH':
                    parsed = 'Library rpath: [%s]' % tag.rpath
                elif tag.entry.d_tag == 'DT_RUNPATH':
                    parsed = 'Library runpath: [%s]' % tag.runpath
                elif tag.entry.d_tag == 'DT_SONAME':
                    parsed = 'Library soname: [%s]' % tag.soname
                elif tag.entry.d_tag.endswith(('SZ', 'ENT')):
                    parsed = '%i (bytes)' % tag['d_val']
                elif tag.entry.d_tag.endswith(('NUM', 'COUNT')):
                    parsed = '%i' % tag['d_val']
                elif tag.entry.d_tag == 'DT_PLTREL':
                    s = describe_dyn_tag(tag.entry.d_val)
                    if s.startswith('DT_'):
                        s = s[3:]
                    parsed = '%s' % s
                else:
                    parsed = '%#x' % tag['d_val']
                tmp_dict.setdefault("tag", self._format_hex(ENUM_D_TAG.get(tag.entry.d_tag, tag.entry.d_tag), fullhex=True, lead0x=True))
                tmp_dict.setdefault("type", tag.entry.d_tag[3:])
                tmp_dict.setdefault("value", parsed)
                if tmp_dict not in dynamic_tags:
                    dynamic_tags.append(tmp_dict)

        return dynamic_tags

    def display_notes(self):
        """ Display the notes contained in the file
        """
        notes = list()
        for segment in self.elffile.iter_segments():
            if isinstance(segment, NoteSegment):
                for note in segment.iter_notes():
                    tmp_dict = dict()
                    #notes.append("\nDisplaying notes found at file offset %s with length %s:" % (
                    #          self._format_hex(note['n_offset'], fieldsize=8),
                    #          self._format_hex(note['n_size'], fieldsize=8)
                    #))
                    #notes.append('  Owner                 Data size Description\n')
                    tmp_dict["owner"] = note['n_name']
                    tmp_dict["size"] = self._format_hex(note['n_descsz'], fieldsize=8)
                    tmp_dict["note"] = describe_note(note)
                    tmp_dict["name"] = note['n_name']
                    notes.append(tmp_dict)
                    """
                    notes.append('  %s%s %s\t%s\n' % (
                          note['n_name'], ' ' * (20 - len(note['n_name'])),
                          self._format_hex(note['n_descsz'], fieldsize=8),
                          describe_note(note)))
                    """
        return notes

    def display_relocations(self):
        """ Display the relocations contained in the file
        """
        reloc = list()
        has_relocation_sections = False
        for section in self.elffile.iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            has_relocation_sections = True
            #reloc += "\nRelocation section '%s' at offset %s contains %s entries:\n" % (
            #    section.name,
            #    self._format_hex(section['sh_offset']),
            #    section.num_relocations())
            """
            if section.is_RELA():
                reloc += "  Offset          Info           Type           Sym. Value    Sym. Name + Addend\n"
            else:
                reloc += " Offset     Info    Type            Sym.Value  Sym. Name\n"
            """
            # The symbol table section pointed to in sh_link
            symtable = self.elffile.get_section(section['sh_link'])
            section_dict = list()
            for rel in section.iter_relocations():
                tmp_dict = dict()

                hexwidth = 8 if self.elffile.elfclass == 32 else 12
                tmp_dict["offset"] = self._format_hex(rel['r_offset'], fieldsize=hexwidth, lead0x=False)
                tmp_dict["info"] = self._format_hex(rel['r_info'], fieldsize=hexwidth, lead0x=False)
                tmp_dict["type"] = describe_reloc_type(rel['r_info_type'], self.elffile)

                if rel['r_info_sym'] == 0:
                    tmp_dict["value"] = ""
                    tmp_dict["name"] = ""
                    continue

                symbol = symtable.get_symbol(rel['r_info_sym'])
                # Some symbols have zero 'st_name', so instead what's used is
                # the name of the section they point at
                if symbol['st_name'] == 0:
                    symsec = self.elffile.get_section(symbol['st_shndx'])
                    symbol_name = symsec.name
                else:
                    symbol_name = symbol.name

                tmp_dict["value"] = self._format_hex(symbol['st_value'], fullhex=True, lead0x=False)
                tmp_dict["name"] = symbol_name
                """
                if section.is_RELA():
                    reloc += str(' %s %x\n' % (
                        '+' if rel['r_addend'] >= 0 else '-',
                        abs(rel['r_addend'])))
                """
                if tmp_dict not in section_dict:
                    section_dict.append(tmp_dict)

            reloc.append({"name":section.name, "entries": section_dict})

        return reloc

    def _format_hex(self, addr, fieldsize=None, fullhex=False, lead0x=True, alternate=False):
        """ Format an address into a hexadecimal string.

            fieldsize:
                Size of the hexadecimal field (with leading zeros to fit the
                address into. For example with fieldsize=8, the format will
                be %08x
                If None, the minimal required field size will be used.

            fullhex:
                If True, override fieldsize to set it to the maximal size
                needed for the elfclass

            lead0x:
                If True, leading 0x is added

            alternate:
                If True, override lead0x to emulate the alternate
                hexadecimal form specified in format string with the #
                character: only non-zero values are prefixed with 0x.
                This form is used by readelf.
        """
        if alternate:
            if addr == 0:
                lead0x = False
            else:
                lead0x = True
                fieldsize -= 2

        s = '0x' if lead0x else ''
        if fullhex:
            fieldsize = 8 if self.elffile.elfclass == 32 else 16
        if fieldsize is None:
            field = '%x'
        else:
            field = '%' + '0%sx' % fieldsize
        return s + field % addr

    def _init_versioninfo(self):
        """ Search and initialize informations about version related sections
            and the kind of versioning used (GNU or Solaris).
        """

        if self._versioninfo is not None:
            return self._versioninfo

        self._versioninfo = {'versym': None, 'verdef': None,
                             'verneed': None, 'type': None}

        for section in self.elffile.iter_sections():
            if isinstance(section, GNUVerSymSection):
                self._versioninfo['versym'] = section
            elif isinstance(section, GNUVerDefSection):
                self._versioninfo['verdef'] = section
            elif isinstance(section, GNUVerNeedSection):
                self._versioninfo['verneed'] = section
            elif isinstance(section, DynamicSection):
                for tag in section.iter_tags():
                    if tag['d_tag'] == 'DT_VERSYM':
                        self._versioninfo['type'] = 'GNU'
                        break

        if not self._versioninfo['type'] and (
                self._versioninfo['verneed'] or self._versioninfo['verdef']):
            self._versioninfo['type'] = 'Solaris'


    def display_version_info(self):
        """ Display the version info contained in the file
        """
        info = str()
        self._init_versioninfo()

        if not self._versioninfo['type']:
            info += "\nNo version information found in this file.\n"
            return

        for section in self.elffile.iter_sections():
            if isinstance(section, GNUVerSymSection):
                info += self._print_version_section_header(
                    section, 'Version symbols', lead0x=False)

                num_symbols = section.num_symbols()

                # Symbol version info are printed four by four entries
                for idx_by_4 in range(0, num_symbols, 4):

                    self._emit('  %03x:' % idx_by_4)

                    for idx in range(idx_by_4, min(idx_by_4 + 4, num_symbols)):

                        symbol_version = self._symbol_version(idx)
                        if symbol_version['index'] == 'VER_NDX_LOCAL':
                            version_index = 0
                            version_name = '(*local*)'
                        elif symbol_version['index'] == 'VER_NDX_GLOBAL':
                            version_index = 1
                            version_name = '(*global*)'
                        else:
                            version_index = symbol_version['index']
                            version_name = '(%(name)s)' % symbol_version

                        visibility = 'h' if symbol_version['hidden'] else ' '

                        info += str('%4x%s%-13s\n' % (
                            version_index, visibility, version_name))

                    info += "\n"

            elif isinstance(section, GNUVerDefSection):
                info += self._print_version_section_header(
                    section, 'Version definition', indent=2)

                offset = 0
                for verdef, verdaux_iter in section.iter_versions():
                    verdaux = next(verdaux_iter)

                    name = verdaux.name
                    if verdef['vd_flags']:
                        flags = describe_ver_flags(verdef['vd_flags'])
                        # Mimic exactly the readelf output
                        flags += ' '
                    else:
                        flags = 'none'

                    info +='  %s: Rev: %i  Flags: %s  Index: %i  Cnt: %i  Name: %s\n' % (
                            self._format_hex(offset, fieldsize=6,
                                             alternate=True),
                            verdef['vd_version'], flags, verdef['vd_ndx'],
                            verdef['vd_cnt'], name)

                    verdaux_offset = (
                            offset + verdef['vd_aux'] + verdaux['vda_next'])
                    for idx, verdaux in enumerate(verdaux_iter, start=1):
                        info += '  %s: Parent %i: %s\n' %  \
                            (self._format_hex(verdaux_offset, fieldsize=4),
                                              idx, verdaux.name)
                        verdaux_offset += verdaux['vda_next']

                    offset += verdef['vd_next']

            elif isinstance(section, GNUVerNeedSection):
                info += self._print_version_section_header(section, 'Version needs')

                offset = 0
                for verneed, verneed_iter in section.iter_versions():

                    info += '  %s: Version: %i  File: %s  Cnt: %i\n' % (
                            self._format_hex(offset, fieldsize=6,
                                             alternate=True),
                            verneed['vn_version'], verneed.name,
                            verneed['vn_cnt'])

                    vernaux_offset = offset + verneed['vn_aux']
                    for idx, vernaux in enumerate(verneed_iter, start=1):
                        if vernaux['vna_flags']:
                            flags = describe_ver_flags(vernaux['vna_flags'])
                            # Mimic exactly the readelf output
                            flags += ' '
                        else:
                            flags = 'none'

                        info +='  %s:   Name: %s  Flags: %s  Version: %i\n' % (
                                self._format_hex(vernaux_offset, fieldsize=4),
                                vernaux.name, flags,
                                vernaux['vna_other'])

                        vernaux_offset += vernaux['vna_next']

                    offset += verneed['vn_next']

            return info

    def _symbol_version(self, nsym):
        """ Return a dict containing information on the
                   or None if no version information is available
        """
        symbol_version = str()
        self._init_versioninfo()

        symbol_version = dict.fromkeys(('index', 'name', 'filename', 'hidden'))

        if (not self._versioninfo['versym'] or
                nsym >= self._versioninfo['versym'].num_symbols()):
            return None

        symbol = self._versioninfo['versym'].get_symbol(nsym)
        index = symbol.entry['ndx']
        if not index in ('VER_NDX_LOCAL', 'VER_NDX_GLOBAL'):
            index = int(index)

            if self._versioninfo['type'] == 'GNU':
                # In GNU versioning mode, the highest bit is used to
                # store wether the symbol is hidden or not
                if index & 0x8000:
                    index &= ~0x8000
                    symbol_version['hidden'] = True

            if (self._versioninfo['verdef'] and
                    index <= self._versioninfo['verdef'].num_versions()):
                _, verdaux_iter = \
                        self._versioninfo['verdef'].get_version(index)
                symbol_version['name'] = next(verdaux_iter).name
            else:
                verneed, vernaux = \
                        self._versioninfo['verneed'].get_version(index)
                symbol_version['name'] = vernaux.name
                symbol_version['filename'] = verneed.name

        symbol_version['index'] = index
        return symbol_version

    '''
    def display_hex_dump(self, section_spec):
        """ Display a hex dump of a section. section_spec is either a section
            number or a name.
        """
        section = self._section_from_spec(section_spec)
        if section is None:
            self._emitline("Section '%s' does not exist in the file!" % (
                section_spec))
            return
        if section['sh_type'] == 'SHT_NOBITS':
            self._emitline("\nSection '%s' has no data to dump." % (
                section_spec))
            return

        self._emitline("\nHex dump of section '%s':" % section.name)
        self._note_relocs_for_section(section)
        addr = section['sh_addr']
        data = section.data()
        dataptr = 0

        while dataptr < len(data):
            bytesleft = len(data) - dataptr
            # chunks of 16 bytes per line
            linebytes = 16 if bytesleft > 16 else bytesleft

            self._emit('  %s ' % self._format_hex(addr, fieldsize=8))
            for i in range(16):
                if i < linebytes:
                    self._emit('%2.2x' % byte2int(data[dataptr + i]))
                else:
                    self._emit('  ')
                if i % 4 == 3:
                    self._emit(' ')

            for i in range(linebytes):
                c = data[dataptr + i : dataptr + i + 1]
                if byte2int(c[0]) >= 32 and byte2int(c[0]) < 0x7f:
                    self._emit(bytes2str(c))
                else:
                    self._emit(bytes2str(b'.'))

            self._emitline()
            addr += linebytes
            dataptr += linebytes

        self._emitline()

    def display_string_dump(self, section_spec):
        """ Display a strings dump of a section. section_spec is either a
            section number or a name.
        """
        section = self._section_from_spec(section_spec)
        if section is None:
            self._emitline("Section '%s' does not exist in the file!" % (
                section_spec))
            return
        if section['sh_type'] == 'SHT_NOBITS':
            self._emitline("\nSection '%s' has no data to dump." % (
                section_spec))
            return

        self._emitline("\nString dump of section '%s':" % section.name)

        found = False
        data = section.data()
        dataptr = 0

        while dataptr < len(data):
            while ( dataptr < len(data) and
                    not (32 <= byte2int(data[dataptr]) <= 127)):
                dataptr += 1

            if dataptr >= len(data):
                break

            endptr = dataptr
            while endptr < len(data) and byte2int(data[endptr]) != 0:
                endptr += 1

            found = True
            self._emitline('  [%6x]  %s' % (
                dataptr, bytes2str(data[dataptr:endptr])))

            dataptr = endptr

        if not found:
            self._emitline('  No strings found in this section.')
        else:
            self._emitline()

    def display_debug_dump(self, dump_what):
        """ Dump a DWARF section
        """
        self._init_dwarfinfo()
        if self._dwarfinfo is None:
            return

        set_global_machine_arch(self.elffile.get_machine_arch())

        if dump_what == 'info':
            self._dump_debug_info()
        elif dump_what == 'decodedline':
            self._dump_debug_line_programs()
        elif dump_what == 'frames':
            self._dump_debug_frames()
        elif dump_what == 'frames-interp':
            self._dump_debug_frames_interp()
        elif dump_what == 'aranges':
            self._dump_debug_aranges()
        else:
            self._emitline('debug dump not yet supported for "%s"' % dump_what)

    def _print_version_section_header(self, version_section, name, lead0x=True, indent=1):
        """ Print a section header of one version related section (versym,
            verneed or verdef) with some options to accomodate readelf
            little differences between each header (e.g. indentation
            and 0x prefixing).
        """
        line = str()
        if hasattr(version_section, 'num_versions'):
            num_entries = version_section.num_versions()
        else:
            num_entries = version_section.num_symbols()

        line += "\n%s section '%s' contains %s entries:\n" %  \
            (name, version_section.name, num_entries)
        line += "%sAddr: %s  Offset: %s  Link: %i (%s)\n" % (
            ' ' * indent,
            self._format_hex(
                version_section['sh_addr'], fieldsize=16, lead0x=lead0x),
            self._format_hex(
                version_section['sh_offset'], fieldsize=6, lead0x=True),
            version_section['sh_link'],
                self.elffile.get_section(version_section['sh_link']).name
        )

        return line

    def _section_from_spec(self, spec):
        """ Retrieve a section given a "spec" (either number or name).
            Return None if no such section exists in the file.
        """
        try:
            num = int(spec)
            if num < self.elffile.num_sections():
                return self.elffile.get_section(num)
            else:
                return None
        except ValueError:
            # Not a number. Must be a name then
            return self.elffile.get_section_by_name(spec)

    def _note_relocs_for_section(self, section):
        """ If there are relocation sections pointing to the givne section,
            emit a note about it.
        """
        for relsec in self.elffile.iter_sections():
            if isinstance(relsec, RelocationSection):
                info_idx = relsec['sh_info']
                if self.elffile.get_section(info_idx) == section:
                    self._emitline('  Note: This section has relocations against it, but these have NOT been applied to this dump.')
                    return

    def _init_dwarfinfo(self):
        """ Initialize the DWARF info contained in the file and assign it to
            self._dwarfinfo.
            Leave self._dwarfinfo at None if no DWARF info was found in the file
        """
        if self._dwarfinfo is not None:
            return

        if self.elffile.has_dwarf_info():
            self._dwarfinfo = self.elffile.get_dwarf_info()
        else:
            self._dwarfinfo = None

    def _dump_debug_info(self):
        """ Dump the debugging info section.
        """
        self._emitline('Contents of the %s section:\n' % self._dwarfinfo.debug_info_sec.name)

        # Offset of the .debug_info section in the stream
        section_offset = self._dwarfinfo.debug_info_sec.global_offset

        for cu in self._dwarfinfo.iter_CUs():
            self._emitline('  Compilation Unit @ offset %s:' %
                self._format_hex(cu.cu_offset))
            self._emitline('   Length:        %s (%s)' % (
                self._format_hex(cu['unit_length']),
                '%s-bit' % cu.dwarf_format()))
            self._emitline('   Version:       %s' % cu['version']),
            self._emitline('   Abbrev Offset: %s' % (
                self._format_hex(cu['debug_abbrev_offset']))),
            self._emitline('   Pointer Size:  %s' % cu['address_size'])

            # The nesting depth of each DIE within the tree of DIEs must be
            # displayed. To implement this, a counter is incremented each time
            # the current DIE has children, and decremented when a null die is
            # encountered. Due to the way the DIE tree is serialized, this will
            # correctly reflect the nesting depth
            #
            die_depth = 0
            for die in cu.iter_DIEs():
                self._emitline(' <%s><%x>: Abbrev Number: %s%s' % (
                    die_depth,
                    die.offset,
                    die.abbrev_code,
                    (' (%s)' % die.tag) if not die.is_null() else ''))
                if die.is_null():
                    die_depth -= 1
                    continue

                for attr in itervalues(die.attributes):
                    name = attr.name
                    # Unknown attribute values are passed-through as integers
                    if isinstance(name, int):
                        name = 'Unknown AT value: %x' % name
                    self._emitline('    <%x>   %-18s: %s' % (
                        attr.offset,
                        name,
                        describe_attr_value(
                            attr, die, section_offset)))

                if die.has_children:
                    die_depth += 1

        self._emitline()

    def _dump_debug_line_programs(self):
        """ Dump the (decoded) line programs from .debug_line
            The programs are dumped in the order of the CUs they belong to.
        """
        self._emitline('Decoded dump of debug contents of section %s:\n' % self._dwarfinfo.debug_line_sec.name)

        for cu in self._dwarfinfo.iter_CUs():
            lineprogram = self._dwarfinfo.line_program_for_CU(cu)

            cu_filename = bytes2str(lineprogram['file_entry'][0].name)
            if len(lineprogram['include_directory']) > 0:
                dir_index = lineprogram['file_entry'][0].dir_index
                if dir_index > 0:
                    dir = lineprogram['include_directory'][dir_index - 1]
                else:
                    dir = b'.'
                cu_filename = '%s/%s' % (bytes2str(dir), cu_filename)

            self._emitline('CU: %s:' % cu_filename)
            self._emitline('File name                            Line number    Starting address')

            # Print each state's file, line and address information. For some
            # instructions other output is needed to be compatible with
            # readelf.
            for entry in lineprogram.get_entries():
                state = entry.state
                if state is None:
                    # Special handling for commands that don't set a new state
                    if entry.command == DW_LNS_set_file:
                        file_entry = lineprogram['file_entry'][entry.args[0] - 1]
                        if file_entry.dir_index == 0:
                            # current directory
                            self._emitline('\n./%s:[++]' % (
                                bytes2str(file_entry.name)))
                        else:
                            self._emitline('\n%s/%s:' % (
                                bytes2str(lineprogram['include_directory'][file_entry.dir_index - 1]),
                                bytes2str(file_entry.name)))
                    elif entry.command == DW_LNE_define_file:
                        self._emitline('%s:' % (
                            bytes2str(lineprogram['include_directory'][entry.args[0].dir_index])))
                elif not state.end_sequence:
                    # readelf doesn't print the state after end_sequence
                    # instructions. I think it's a bug but to be compatible
                    # I don't print them too.
                    if lineprogram['version'] < 4:
                        self._emitline('%-35s  %11d  %18s' % (
                            bytes2str(lineprogram['file_entry'][state.file - 1].name),
                            state.line,
                            '0' if state.address == 0 else
                                self._format_hex(state.address)))
                    else:
                        self._emitline('%-35s  %11d  %18s[%d]' % (
                            bytes2str(lineprogram['file_entry'][state.file - 1].name),
                            state.line,
                            '0' if state.address == 0 else
                                self._format_hex(state.address),
                            state.op_index))
                if entry.command == DW_LNS_copy:
                    # Another readelf oddity...
                    self._emitline()

    def _dump_debug_frames(self):
        """ Dump the raw frame information from .debug_frame
        """
        if not self._dwarfinfo.has_CFI():
            return
        self._emitline('Contents of the %s section:' % self._dwarfinfo.debug_frame_sec.name)

        for entry in self._dwarfinfo.CFI_entries():
            if isinstance(entry, CIE):
                self._emitline('\n%08x %s %s CIE' % (
                    entry.offset,
                    self._format_hex(entry['length'], fullhex=True, lead0x=False),
                    self._format_hex(entry['CIE_id'], fullhex=True, lead0x=False)))
                self._emitline('  Version:               %d' % entry['version'])
                self._emitline('  Augmentation:          "%s"' % bytes2str(entry['augmentation']))
                self._emitline('  Code alignment factor: %u' % entry['code_alignment_factor'])
                self._emitline('  Data alignment factor: %d' % entry['data_alignment_factor'])
                self._emitline('  Return address column: %d' % entry['return_address_register'])
                self._emitline()
            else: # FDE
                self._emitline('\n%08x %s %s FDE cie=%08x pc=%s..%s' % (
                    entry.offset,
                    self._format_hex(entry['length'], fullhex=True, lead0x=False),
                    self._format_hex(entry['CIE_pointer'], fullhex=True, lead0x=False),
                    entry.cie.offset,
                    self._format_hex(entry['initial_location'], fullhex=True, lead0x=False),
                    self._format_hex(
                        entry['initial_location'] + entry['address_range'],
                        fullhex=True, lead0x=False)))

            self._emit(describe_CFI_instructions(entry))
        self._emitline()

    def _dump_debug_aranges(self):
        """ Dump the aranges table
        """
        aranges_table = self._dwarfinfo.get_aranges()
        if aranges_table == None:
            return
        # seems redundent, but we need to get the unsorted set of entries to match system readelf
        unordered_entries = aranges_table._get_entries()

        if len(unordered_entries) == 0:
            self._emitline()
            self._emitline("Section '.debug_aranges' has no debugging data.")
            return

        self._emitline('Contents of the %s section:' % self._dwarfinfo.debug_aranges_sec.name)
        self._emitline()
        prev_offset = None
        for entry in unordered_entries:
            if prev_offset != entry.info_offset:
                if entry != unordered_entries[0]:
                    self._emitline('    %s %s' % (
                        self._format_hex(0, fullhex=True, lead0x=False),
                        self._format_hex(0, fullhex=True, lead0x=False)))
                self._emitline('  Length:                   %d' % (entry.unit_length))
                self._emitline('  Version:                  %d' % (entry.version))
                self._emitline('  Offset into .debug_info:  0x%x' % (entry.info_offset))
                self._emitline('  Pointer Size:             %d' % (entry.address_size))
                self._emitline('  Segment Size:             %d' % (entry.segment_size))
                self._emitline()
                self._emitline('    Address            Length')
            self._emitline('    %s %s' % (
                self._format_hex(entry.begin_addr, fullhex=True, lead0x=False),
                self._format_hex(entry.length, fullhex=True, lead0x=False)))
            prev_offset = entry.info_offset
        self._emitline('    %s %s' % (
                self._format_hex(0, fullhex=True, lead0x=False),
                self._format_hex(0, fullhex=True, lead0x=False)))

    def _dump_debug_frames_interp(self):
        """ Dump the interpreted (decoded) frame information from .debug_frame
        """
        if not self._dwarfinfo.has_CFI():
            return

        self._emitline('Contents of the %s section:' % self._dwarfinfo.debug_frame_sec.name)

        for entry in self._dwarfinfo.CFI_entries():
            if isinstance(entry, CIE):
                self._emitline('\n%08x %s %s CIE "%s" cf=%d df=%d ra=%d' % (
                    entry.offset,
                    self._format_hex(entry['length'], fullhex=True, lead0x=False),
                    self._format_hex(entry['CIE_id'], fullhex=True, lead0x=False),
                    bytes2str(entry['augmentation']),
                    entry['code_alignment_factor'],
                    entry['data_alignment_factor'],
                    entry['return_address_register']))
                ra_regnum = entry['return_address_register']
            else: # FDE
                self._emitline('\n%08x %s %s FDE cie=%08x pc=%s..%s' % (
                    entry.offset,
                    self._format_hex(entry['length'], fullhex=True, lead0x=False),
                    self._format_hex(entry['CIE_pointer'], fullhex=True, lead0x=False),
                    entry.cie.offset,
                    self._format_hex(entry['initial_location'], fullhex=True, lead0x=False),
                    self._format_hex(entry['initial_location'] + entry['address_range'],
                        fullhex=True, lead0x=False)))
                ra_regnum = entry.cie['return_address_register']

            # Print the heading row for the decoded table
            self._emit('   LOC')
            self._emit('  ' if entry.structs.address_size == 4 else '          ')
            self._emit(' CFA      ')

            # Decode the table nad look at the registers it describes.
            # We build reg_order here to match readelf's order. In particular,
            # registers are sorted by their number, and the register matching
            # ra_regnum is always listed last with a special heading.
            decoded_table = entry.get_decoded()
            reg_order = sorted(ifilter(
                lambda r: r != ra_regnum,
                decoded_table.reg_order))
            if len(decoded_table.reg_order):

                # Headings for the registers
                for regnum in reg_order:
                    self._emit('%-6s' % describe_reg_name(regnum))
                self._emitline('ra      ')

                # Now include ra_regnum in reg_order to print its values similarly
                # to the other registers.
                reg_order.append(ra_regnum)
            else:
                self._emitline()

            for line in decoded_table.table:
                self._emit(self._format_hex(
                    line['pc'], fullhex=True, lead0x=False))
                self._emit(' %-9s' % describe_CFI_CFA_rule(line['cfa']))

                for regnum in reg_order:
                    if regnum in line:
                        s = describe_CFI_register_rule(line[regnum])
                    else:
                        s = 'u'
                    self._emit('%-6s' % s)
                self._emitline()
        self._emitline()
    '''

class ELF(object):
    """PE analysis."""

    def __init__(self, file_path):
        """@param file_path: file path."""
        self.file_path = file_path
        self.elf = None

    def __get_relocations(self):
        """Gets relocations.
        @return: relocations dict or None.
        """
        relocs = []

        process = subprocess.Popen(["/usr/bin/objdump",self.file_path, "-R"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        # take output
        dump_result = process.communicate()[0]
        # format output
        dump_result = re.split("\n[ ]{0,}", dump_result)

        for i in range(0,len(dump_result)):
            if re.search("00", dump_result[i]):
                relocs.append(filter(None, re.split("\s", dump_result[i])))

        return relocs

    def _get_symbols(self):
        """Gets symbols.
        @return: symbols dict or None.
        """

        libs = []
        entry = []

        # dump dynamic symbols using 'objdump -T'
        process = subprocess.Popen(["/usr/bin/objdump",self.file_path, "-T"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        elf = process.communicate()[0]

        # Format to lines by splitting at '\n'
        elf = re.split("\n[ ]{0,}", elf)

        for i in range(0,len(elf)):
            if re.search("DF \*UND\*", elf[i]):
                entry.append(filter(None, re.split("\s", elf[i])))

        # extract library names
        lib_names = set()
        for e in entry:
            # check for existing library name
            if len(e) > 5:
                # add library to set
                lib_names.add(e[4])
        lib_names.add("None")

        # fetch relocation addresses
        relocs = self.__get_relocations()

        # find all symbols for each lib
        for lib in lib_names:
            symbols = []
            for e in entry:
                if lib == e[4]:
                    symbol = {}
                    symbol["address"] = "0x{0}".format(e[0])
                    symbol["name"] = e[5]

                    # fetch the address from relocation sections if possible
                    for r in relocs:
                        if symbol["name"] in r:
                            symbol["address"] = "0x{0}".format(r[0])
                    symbols.append(symbol)

            if symbols:
                symbol_section = {}
                symbol_section["lib"] = lib
                symbol_section["symbols"] = symbols
                libs.append(symbol_section)

        return libs

    def run(self):
        """Run analysis.
        @return: analysis results dict or None.
        """
        results = {}
        if not os.path.exists(self.file_path):
            return {}


        if HAS_ELFTOOLS is False:
            return {}

        try:
            self.readelf = ReadElf(open(self.file_path, "rb"))
        except Exception as e:
            log.error(e)
            return {}
        do_file_header = True

        results["file_header"] = self.readelf.display_file_header()
        results["section_headers"] = self.readelf.display_section_headers(show_heading=not do_file_header)
        results["program_headers"] = self.readelf.display_program_headers(show_heading=not do_file_header)
        results["dynamic_tags"] = self.readelf.display_dynamic_tags()
        results["symbol_tables"] = self.readelf.display_symbol_tables()
        results["notes"] = self.readelf.display_notes()
        #ToDo add library name per import https://github.com/cuckoosandbox/cuckoo/pull/807/files#diff-033aeda7c00b458591305630264df6d3R604
        results["relocations"] = self.readelf.display_relocations()
        #results["version_info "] = self.readelf.display_version_info()
        return results

class WindowsScriptFile(object):
    """Deobfuscates and interprets Windows Script Files."""
    encoding = [
        1, 2, 0, 1, 2, 0, 2, 0, 0, 2, 0, 2, 1, 0, 2, 0,
        1, 0, 2, 0, 1, 1, 2, 0, 0, 2, 1, 0, 2, 0, 0, 2,
        1, 1, 0, 2, 0, 2, 0, 1, 0, 1, 1, 2, 0, 1, 0, 2,
        1, 0, 2, 0, 1, 1, 2, 0, 0, 1, 1, 2, 0, 1, 0, 2,
    ]

    lookup = [
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
         0x08, 0x7b, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
         0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
         0x32, 0x30, 0x21, 0x29, 0x5b, 0x38, 0x33, 0x3d,
         0x58, 0x3a, 0x35, 0x65, 0x39, 0x5c, 0x56, 0x73,
         0x66, 0x4e, 0x45, 0x6b, 0x62, 0x59, 0x78, 0x5e,
         0x7d, 0x4a, 0x6d, 0x71, 0x00, 0x60, 0x00, 0x53,
         0x00, 0x42, 0x27, 0x48, 0x72, 0x75, 0x31, 0x37,
         0x4d, 0x52, 0x22, 0x54, 0x6a, 0x47, 0x64, 0x2d,
         0x20, 0x7f, 0x2e, 0x4c, 0x5d, 0x7e, 0x6c, 0x6f,
         0x79, 0x74, 0x43, 0x26, 0x76, 0x25, 0x24, 0x2b,
         0x28, 0x23, 0x41, 0x34, 0x09, 0x2a, 0x44, 0x3f,
         0x77, 0x3b, 0x55, 0x69, 0x61, 0x63, 0x50, 0x67,
         0x51, 0x49, 0x4f, 0x46, 0x68, 0x7c, 0x36, 0x70,
         0x6e, 0x7a, 0x2f, 0x5f, 0x4b, 0x5a, 0x2c, 0x57],
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
         0x08, 0x57, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
         0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
         0x2e, 0x47, 0x7a, 0x56, 0x42, 0x6a, 0x2f, 0x26,
         0x49, 0x41, 0x34, 0x32, 0x5b, 0x76, 0x72, 0x43,
         0x38, 0x39, 0x70, 0x45, 0x68, 0x71, 0x4f, 0x09,
         0x62, 0x44, 0x23, 0x75, 0x00, 0x7e, 0x00, 0x5e,
         0x00, 0x77, 0x4a, 0x61, 0x5d, 0x22, 0x4b, 0x6f,
         0x4e, 0x3b, 0x4c, 0x50, 0x67, 0x2a, 0x7d, 0x74,
         0x54, 0x2b, 0x2d, 0x2c, 0x30, 0x6e, 0x6b, 0x66,
         0x35, 0x25, 0x21, 0x64, 0x4d, 0x52, 0x63, 0x3f,
         0x7b, 0x78, 0x29, 0x28, 0x73, 0x59, 0x33, 0x7f,
         0x6d, 0x55, 0x53, 0x7c, 0x3a, 0x5f, 0x65, 0x46,
         0x58, 0x31, 0x69, 0x6c, 0x5a, 0x48, 0x27, 0x5c,
         0x3d, 0x24, 0x79, 0x37, 0x60, 0x51, 0x20, 0x36],
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
         0x08, 0x6e, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
         0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
         0x2d, 0x75, 0x52, 0x60, 0x71, 0x5e, 0x49, 0x5c,
         0x62, 0x7d, 0x29, 0x36, 0x20, 0x7c, 0x7a, 0x7f,
         0x6b, 0x63, 0x33, 0x2b, 0x68, 0x51, 0x66, 0x76,
         0x31, 0x64, 0x54, 0x43, 0x00, 0x3a, 0x00, 0x7e,
         0x00, 0x45, 0x2c, 0x2a, 0x74, 0x27, 0x37, 0x44,
         0x79, 0x59, 0x2f, 0x6f, 0x26, 0x72, 0x6a, 0x39,
         0x7b, 0x3f, 0x38, 0x77, 0x67, 0x53, 0x47, 0x34,
         0x78, 0x5d, 0x30, 0x23, 0x5a, 0x5b, 0x6c, 0x48,
         0x55, 0x70, 0x69, 0x2e, 0x4c, 0x21, 0x24, 0x4e,
         0x50, 0x09, 0x56, 0x73, 0x35, 0x61, 0x4b, 0x58,
         0x3b, 0x57, 0x22, 0x6d, 0x4d, 0x25, 0x28, 0x46,
         0x4a, 0x32, 0x41, 0x3d, 0x5f, 0x4f, 0x42, 0x65],
    ]

    unescape = {
        "#": "\r", "&": "\n", "!": "<", "*": ">", "$": "@",
    }

    script_re = "<\\s*script\\s*.*>.*?<\\s*/\\s*script\\s*>"

    def __init__(self, filepath):
        self.filepath = filepath

    def decode(self, source, start="#@~^", end="^#~@"):
        if start not in source or end not in source:
            return

        o = source.index(start) + len(start) + 8
        end = source.index(end) - 8

        c, m, r = 0, 0, []

        while o < end:
            ch = ord(source[o])
            if source[o] == "@":
                r.append(ord(self.unescape.get(source[o+1], "?")))
                c += r[-1]
                o, m = o + 1, m + 1
            elif ch < 128:
                r.append(self.lookup[self.encoding[m % 64]][ch])
                c += r[-1]
                m = m + 1
            else:
                r.append(ch)

            o = o + 1

        if (c % 2**32) != struct.unpack("I", source[o:o+8].decode("base64"))[0]:
            log.info("Invalid checksum for JScript.Encoded WSF file!")

        return "".join(chr(ch) for ch in r)

    def run(self):
        ret = []
        source = open(self.filepath, "rb").read()

        # Get rid of superfluous comments.
        source = re.sub("/\\*.*?\\*/", "", source, flags=re.S)

        for script in re.findall(self.script_re, source, re.I | re.S):
            try:
                x = bs4.BeautifulSoup(script, "html.parser")
                language = x.script.attrs.get("language", "").lower()
            except:
                language = None

            # We can't rely on bs4 or any other HTML/XML parser to provide us
            # with the raw content of the xml tag as they decode html entities
            # and all that, leaving us with a corrupted string.
            source = re.match("<.*>(.*)</.*>$", script, re.S).group(0)

            # Decode JScript.Encode encoding.
            if language in ("jscript.encode", "vbscript.encode"):
                source = self.decode(source)

            ret.append(to_unicode(source))

        return ret

class OfficeDocument(object):
    """Static analysis of Microsoft Office documents."""
    deobf = [
        # [
        #    # Chr(65) -> "A"
        #    "Chr\\(\\s*(?P<chr>[0-9]+)\\s*\\)",
        #    lambda x: '"%c"' % int(x.group("chr")),
        #    0,
        # ],
        [
            # "A" & "B" -> "AB"
            "\\\"(?P<a>.*?)\\\"\\s+\\&\\s+\\\"(?P<b>.*?)\\\"",
            lambda x: '"%s%s"' % (x.group("a"), x.group("b")),
            0,
        ],
    ]

    eps_comments = "\\(([\\w\\s]+)\\)"

    def __init__(self, filepath):
        self.filepath = filepath
        self.files = {}

    def get_macros(self):
        """Get embedded Macros if this is an Office document."""
        try:
            p = oletools.olevba.VBA_Parser(self.filepath)
        except TypeError:
            return

        # We're not interested in plaintext.
        if p.type == "Text":
            return

        try:
            for f, s, v, c in p.extract_macros():
                yield {
                    "stream": s,
                    "filename": v.decode("latin-1"),
                    "orig_code": c.decode("latin-1"),
                    "deobf": self.deobfuscate(c.decode("latin-1")),
                }
        except ValueError as e:
            log.warning(
                "Error extracting macros from office document (this is an "
                "issue with oletools - please report upstream): %s", e
            )

    def deobfuscate(self, code):
        """Bruteforce approach of regex-based deobfuscation."""
        changes = 1
        while changes:
            changes = 0

            for pattern, repl, flags in self.deobf:
                count = 1
                while count:
                    code, count = re.subn(pattern, repl, code, flags=flags)
                    changes += count

        return code

    def unpack_docx(self):
        """Unpacks .docx-based zip files."""
        try:
            z = zipfile.ZipFile(self.filepath)
            for name in z.namelist():
                self.files[name] = z.read(name)
        except:
            return

    def extract_eps(self):
        """Extract some information from Encapsulated Post Script files."""
        ret = []
        for filename, content in self.files.items():
            if filename.lower().endswith(".eps"):
                ret.extend(re.findall(self.eps_comments, content))
        return ret

    def run(self):
        self.unpack_docx()

        return {
            "macros": list(self.get_macros()),
            "eps": self.extract_eps(),
        }

class PdfDocument(object):
    """Static analysis of PDF documents."""

    def __init__(self, filepath):
        self.filepath = filepath

    def _parse_string(self, s):
        # Big endian.
        if s.startswith(u"\xfe\xff"):
            return s[2:].encode("latin-1").decode("utf-16be")

        # Little endian.
        if s.startswith(u"\xff\xfe"):
            return s[2:].encode("latin-1").decode("utf-16le")

        return s

    def _sanitize(self, d, key):
        return self._parse_string(d.get(key, "").decode("latin-1"))

    def walk_object(self, obj, entry):
        if isinstance(obj, peepdf.PDFCore.PDFStream):
            stream = obj.decodedStream

            # Is this actually Javascript code?
            if not peepdf.JSAnalysis.isJavascript(stream):
                return

            javascript = stream.decode("latin-1")
            entry["javascript"].append({
                "orig_code": javascript,
                "beautified": jsbeautify(javascript),
                "urls": [],
            })
            return

        if isinstance(obj, peepdf.PDFCore.PDFDictionary):
            for url in obj.urlsFound:
                entry["urls"].append(self._parse_string(url))

            for url in obj.uriList:
                entry["urls"].append(self._parse_string(url))

            # TODO We should probably add some more criteria here.
            uri_obj = obj.elements.get("/URI")
            if uri_obj:
                if isinstance(uri_obj, peepdf.PDFCore.PDFString):
                    entry["urls"].append(uri_obj.value)
                else:
                    log.warning(
                        "Identified a potential URL, but its associated "
                        "type is not a string?"
                    )

            for element in obj.elements.values():
                self.walk_object(element, entry)
            return

        if isinstance(obj, peepdf.PDFCore.PDFArray):
            for element in obj.elements:
                self.walk_object(element, entry)
            return

    def run(self):
        p = peepdf.PDFCore.PDFParser()
        r, f = p.parse(
            self.filepath, forceMode=True,
            looseMode=True, manualAnalysis=False
        )
        if r:
            log.warning("Error parsing PDF file, error code %s", r)
            return

        ret = []

        for version in xrange(f.updates + 1):
            md = f.getBasicMetadata(version)
            row = {
                "version": version,
                "creator": self._sanitize(md, "creator"),
                "creation": self._sanitize(md, "creation"),
                "title": self._sanitize(md, "title"),
                "subject": self._sanitize(md, "subject"),
                "producer": self._sanitize(md, "producer"),
                "author": self._sanitize(md, "author"),
                "modification": self._sanitize(md, "modification"),
                "javascript": [],
                "urls": [],
            }

            for obj in f.body[version].objects.values():
                self.walk_object(obj.object, row)

            row["urls"] = sorted(set(row["urls"]))
            ret.append(row)

        return ret

class LnkHeader(Structure):
    _fields_ = [
        ("signature", ctypes.c_ubyte * 4),
        ("guid", ctypes.c_ubyte * 16),
        ("flags", ctypes.c_uint),
        ("attrs", ctypes.c_uint),
        ("creation", ctypes.c_ulonglong),
        ("access", ctypes.c_ulonglong),
        ("modified", ctypes.c_ulonglong),
        ("target_len", ctypes.c_uint),
        ("icon_len", ctypes.c_uint),
        ("show_window", ctypes.c_uint),
        ("hotkey", ctypes.c_uint),
    ]

class LnkEntry(Structure):
    _fields_ = [
        ("length", ctypes.c_uint),
        ("first_offset", ctypes.c_uint),
        ("volume_flags", ctypes.c_uint),
        ("local_volume", ctypes.c_uint),
        ("base_path", ctypes.c_uint),
        ("net_volume", ctypes.c_uint),
        ("path_remainder", ctypes.c_uint),
    ]

class LnkShortcut(object):
    signature = [0x4c, 0x00, 0x00, 0x00]
    guid = [
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
    ]
    flags = [
        "shellidlist", "references", "description",
        "relapath", "workingdir", "cmdline", "icon",
    ]
    attrs = [
        "readonly", "hidden", "system", None, "directory", "archive",
        "ntfs_efs", "normal", "temporary", "sparse", "reparse", "compressed",
        "offline", "not_indexed", "encrypted",
    ]

    def __init__(self, filepath):
        self.filepath = filepath

    def read_uint16(self, offset):
        return struct.unpack("H", self.buf[offset:offset+2])[0]

    def read_uint32(self, offset):
        return struct.unpack("I", self.buf[offset:offset+4])[0]

    def read_stringz(self, offset):
        return self.buf[offset:self.buf.index("\x00", offset)]

    def read_string16(self, offset):
        length = self.read_uint16(offset) * 2
        ret = self.buf[offset+2:offset+2+length].decode("utf16")
        return offset + 2 + length, ret

    def run(self):
        self.buf = buf = open(self.filepath, "rb").read()
        if len(buf) < ctypes.sizeof(LnkHeader):
            log.warning("Provided .lnk file is corrupted or incomplete.")
            return

        header = LnkHeader.from_buffer_copy(buf[:ctypes.sizeof(LnkHeader)])
        if header.signature[:] != self.signature:
            log.warning(
                "Provided .lnk file is not a Microsoft Shortcut "
                "(invalid signature)!"
            )
            return

        if header.guid[:] != self.guid:
            log.warning(
                "Provided .lnk file is not a Microsoft Shortcut "
                "(invalid guid)!"
            )
            return

        ret = {
            "flags": {},
            "attrs": []
        }

        for x in xrange(7):
            ret["flags"][self.flags[x]] = bool(header.flags & (1 << x))

        for x in xrange(14):
            if header.attrs & (1 << x):
                ret["attrs"].append(self.attrs[x])

        offset = 78 + self.read_uint16(76)
        off = LnkEntry.from_buffer_copy(buf[offset:offset+28])

        # Local volume.
        if off.volume_flags & 1:
            ret["basepath"] = self.read_stringz(offset + off.base_path)
        # Network volume.
        else:
            ret["net_share"] = self.read_stringz(offset + off.net_volume + 20)
            network_drive = self.read_uint32(offset + off.net_volume + 12)
            if network_drive:
                ret["network_drive"] = self.read_stringz(
                    offset + network_drive
                )

        ret["remaining_path"] = self.read_stringz(offset + off.path_remainder)

        extra = offset + off.length
        if ret["flags"]["description"]:
            extra, ret["description"] = self.read_string16(extra)
        if ret["flags"]["relapath"]:
            extra, ret["relapath"] = self.read_string16(extra)
        if ret["flags"]["workingdir"]:
            extra, ret["workingdir"] = self.read_string16(extra)
        if ret["flags"]["cmdline"]:
            extra, ret["cmdline"] = self.read_string16(extra)
        if ret["flags"]["icon"]:
            extra, ret["icon"] = self.read_string16(extra)
        return ret

def _pdf_worker(filepath):
    return PdfDocument(filepath).run()

class Static(Processing):
    """Static analysis."""

    office_ext = [
        "doc", "docm", "dotm", "docx", "ppt", "pptm", "pptx", "potm",
        "ppam", "ppsm", "xls", "xlsm", "xlsx",
    ]

    def run(self):
        """Run analysis.
        @return: results dict.
        """
        self.key = "static"
        static = {}

        if self.task["category"] == "file":
            if not os.path.exists(self.file_path):
                return

            f = File(self.file_path)
            filename = os.path.basename(self.task["target"])
        elif self.task["category"] == "archive":
            if not os.path.exists(self.file_path):
                return

            f = Archive(self.file_path).get_file(
                self.task["options"]["filename"]
            )
            filename = os.path.basename(self.task["options"]["filename"])
        else:
            return

        if filename:
            ext = filename.split(os.path.extsep)[-1].lower()
        else:
            ext = None

        package = self.task.get("package")

        if ext == "elf" or "ELF" in f.get_type():
            static.update(ELF(f.file_path).run())
            #static["keys"] = f.get_keys()

        if package == "exe" or ext == "exe" or "PE32" in f.get_type():
            static.update(PortableExecutable(f.file_path).run())
            static["keys"] = f.get_keys()

        if package == "wsf" or ext == "wsf":
            static["wsf"] = WindowsScriptFile(f.file_path).run()

        if package in ("doc", "ppt", "xls") or ext in self.office_ext:
            static["office"] = OfficeDocument(f.file_path).run()

        if package == "pdf" or ext == "pdf":
            static["pdf"] = dispatch(
                _pdf_worker, (f.file_path,),
                timeout=self.options.pdf_timeout
            )

        if package == "lnk" or ext == "lnk":
            static["lnk"] = LnkShortcut(f.file_path).run()

        return static
