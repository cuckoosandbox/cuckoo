# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import bs4
import ctypes
import datetime
import logging
import oletools.olevba
import oletools.oleobj
import os
import peepdf.JSAnalysis
import peepdf.PDFCore
import pefile
import peutils
import re
import sflock
import struct
import zipfile
import zlib

try:
    import M2Crypto
    HAVE_MCRYPTO = True
except ImportError:
    HAVE_MCRYPTO = False

from cuckoo.common.abstracts import Processing
from cuckoo.common.objects import Archive, File
from cuckoo.common.structures import LnkHeader, LnkEntry
from cuckoo.common.utils import convert_to_printable, to_unicode, jsbeautify
from cuckoo.core.extract import ExtractManager
from cuckoo.misc import cwd, dispatch

from elftools.common.exceptions import ELFError
from elftools.elf.constants import E_FLAGS
from elftools.elf.descriptions import (
    describe_ei_class, describe_ei_data, describe_ei_version,
    describe_ei_osabi, describe_e_type, describe_e_machine,
    describe_e_version_numeric, describe_p_type, describe_p_flags,
    describe_sh_type, describe_dyn_tag, describe_symbol_type,
    describe_symbol_bind, describe_note, describe_reloc_type
)
from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_D_TAG
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from elftools.elf.segments import NoteSegment

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
        """Get filetype, use libmagic if available.
        @param data: data to be analyzed.
        @return: file type or None.
        """
        return sflock.magic.from_buffer(data)

    def _get_peid_signatures(self):
        """Get PEID signatures.
        @return: matched signatures or None.
        """
        try:
            sig_path = cwd("peutils", "UserDB.TXT", private=True)
            signatures = peutils.SignatureDatabase(sig_path)
            return signatures.match(self.pe, ep_only=True)
        except:
            return None

    def _get_imported_symbols(self):
        """Get imported symbols.
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
        """Get exported symbols.
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
        """Get sections.
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
        """Get imphash.
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

    def __init__(self, filepath, task_id):
        self.filepath = filepath
        self.files = {}
        self.ex = ExtractManager.for_task(task_id)

    def get_macros(self):
        """Get embedded Macros if this is an Office document."""
        try:
            p = oletools.olevba.VBA_Parser(self.filepath)
        except (TypeError, oletools.olevba.FileOpenError, zlib.error):
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

        self.ex.peek_office(self.files)

        return {
            "macros": list(self.get_macros()),
            "eps": self.extract_eps(),
        }

class PdfDocument(object):
    """Static analysis of PDF documents."""

    def __init__(self, filepath):
        self.filepath = filepath

    def _parse_string(self, s):
        if isinstance(s, unicode):
            # Big endian.
            if s.startswith(u"\xfe\xff"):
                return s[2:].encode("latin-1").decode("utf-16be")

            # Little endian.
            if s.startswith(u"\xff\xfe"):
                return s[2:].encode("latin-1").decode("utf-16le")

        if isinstance(s, str):
            # Big endian.
            if s.startswith("\xfe\xff"):
                return s[2:].decode("utf-16be")

            # Little endian.
            if s.startswith("\xff\xfe"):
                return s[2:].decode("utf-16le")

        try:
            return s.decode("latin-1")
        except (UnicodeDecodeError, UnicodeEncodeError):
            return s

    def _sanitize(self, d, key):
        return self._parse_string(d.get(key, "").decode("latin-1"))

    def walk_object(self, obj, entry):
        if isinstance(obj, peepdf.PDFCore.PDFDictionary):
            for url in obj.urlsFound:
                entry["urls"].append(self._parse_string(url))

            for url in obj.uriList:
                entry["urls"].append(self._parse_string(url))

            # TODO We should probably add some more criteria here.
            uri_obj = obj.elements.get("/URI")
            if uri_obj:
                if isinstance(uri_obj, peepdf.PDFCore.PDFString):
                    entry["urls"].append(self._parse_string(uri_obj.value))
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

    def get_javascript(self, obj, f, version):
        if not isinstance(obj.object, peepdf.PDFCore.PDFDictionary):
            return

        if "/JS" not in obj.object.elements:
            return

        ref = obj.object.elements["/JS"]

        if isinstance(ref, peepdf.PDFCore.PDFString):
            return {
                "orig_code": self._parse_string("".join(ref.getJSCode())),
                "beautified": self._parse_string(
                    jsbeautify("".join(ref.getJSCode()))
                ),
                "urls": []
            }

        if not isinstance(ref, peepdf.PDFCore.PDFReference):
            log.warning("PDFObject: can't follow type %s", ref)
            return

        if ref.id not in f.body[version].objects:
            log.warning("PDFObject: Reference is broken, can't follow")
            return

        obj = f.body[version].objects[ref.id]
        return {
            "orig_code": self._parse_string("".join(obj.object.getJSCode())),
            "beautified": self._parse_string(
                jsbeautify("".join(obj.object.getJSCode()))
            ),
            "urls": []
        }

    def get_attachments(self, obj, f, version):
        if not isinstance(obj.object, peepdf.PDFCore.PDFDictionary):
            return

        if "/F" not in obj.object.elements:
            return
        if "/EF" not in obj.object.elements:
            return

        filename = obj.object.elements["/F"]
        if not isinstance(filename, peepdf.PDFCore.PDFString):
            return

        ref = obj.object.elements["/EF"]
        if not isinstance(ref, peepdf.PDFCore.PDFDictionary):
            return

        if "/F" not in ref.elements:
            return

        ref = ref.elements["/F"]
        if not isinstance(ref, peepdf.PDFCore.PDFReference):
            return

        if ref.id not in f.body[version].objects:
            return

        obj = f.body[version].objects[ref.id]
        return {
            # TODO Extract "obj.object.decodedStream" as Extracted Artifact?
            # "contents": obj.object.decodedStream,
            "filename": filename.value,
        }

    def get_openaction(self, obj, f, version):
        if not isinstance(obj.object, peepdf.PDFCore.PDFDictionary):
            return

        if "/OpenAction" not in obj.object.elements:
            return

        action = obj.object.elements["/OpenAction"]

        if isinstance(action, peepdf.PDFCore.PDFDictionary):
            return action.value

        if isinstance(action, peepdf.PDFCore.PDFReference):
            referenced = f.body[version].objects.get(action.id)
            if isinstance(referenced, peepdf.PDFCore.PDFIndirectObject):
                obj = referenced.object
                if isinstance(obj, peepdf.PDFCore.PDFDictionary):
                    return obj.value

        return None

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
                "attachments": [],
                "openaction": None,
            }

            for obj in f.body[version].objects.values():
                action = self.get_openaction(obj, f, version)
                if action:
                    row["openaction"] = action

                js = self.get_javascript(obj, f, version)
                if js:
                    row["javascript"].append(js)

                att = self.get_attachments(obj, f, version)
                if att:
                    row["attachments"].append(att)

                self.walk_object(obj.object, row)

            row["urls"] = sorted(set(row["urls"]))
            ret.append(row)

        return ret

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

    def __init__(self, filepath=None):
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
        buf = self.buf = open(self.filepath, "rb").read()
        if len(buf) < ctypes.sizeof(LnkHeader):
            log.warning("Provided .lnk file is corrupted or incomplete.")
            return

        header = LnkHeader.from_buffer_copy(buf[:ctypes.sizeof(LnkHeader)])
        if header.signature[:] != self.signature:
            return

        if header.guid[:] != self.guid:
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
        if len(buf) < offset + 28:
            log.warning("Provided .lnk file is corrupted or incomplete.")
            return

        off = LnkEntry.from_buffer_copy(buf[offset:offset + 28])

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

class ELF(object):
    def __init__(self, file_path):
        self.file_path = file_path
        self.elf = None
        self.result = {}

    def run(self):
        try:
            self.elf = ELFFile(open(self.file_path, "rb"))
            self.result["file_header"] = self._get_file_header()
            self.result["section_headers"] = self._get_section_headers()
            self.result["program_headers"] = self._get_program_headers()
            self.result["dynamic_tags"] = self._get_dynamic_tags()
            self.result["symbol_tables"] = self._get_symbol_tables()
            self.result["relocations"] = self._get_relocations()
            self.result["notes"] = self._get_notes()
            # TODO: add library name per import (see #807)
        except ELFError as e:
            if e.message != "Magic number does not match":
                raise

        return self.result

    def _get_file_header(self):
        return {
            "magic": convert_to_printable(self.elf.e_ident_raw[:4]),
            "class": describe_ei_class(self.elf.header.e_ident["EI_CLASS"]),
            "data": describe_ei_data(self.elf.header.e_ident["EI_DATA"]),
            "ei_version": describe_ei_version(self.elf.header.e_ident["EI_VERSION"]),
            "os_abi": describe_ei_osabi(self.elf.header.e_ident["EI_OSABI"]),
            "abi_version": self.elf.header.e_ident["EI_ABIVERSION"],
            "type": describe_e_type(self.elf.header["e_type"]),
            "machine": describe_e_machine(self.elf.header["e_machine"]),
            "version": describe_e_version_numeric(self.elf.header["e_version"]),
            "entry_point_address": self._print_addr(self.elf.header["e_entry"]),
            "start_of_program_headers": self.elf.header["e_phoff"],
            "start_of_section_headers": self.elf.header["e_shoff"],
            "flags": "{}{}".format(
                self._print_addr(self.elf.header["e_flags"]),
                self._decode_flags(self.elf.header["e_flags"])
            ),
            "size_of_this_header": self.elf.header["e_ehsize"],
            "size_of_program_headers": self.elf.header["e_phentsize"],
            "number_of_program_headers": self.elf.header["e_phnum"],
            "size_of_section_headers": self.elf.header["e_shentsize"],
            "number_of_section_headers": self.elf.header["e_shnum"],
            "section_header_string_table_index": self.elf.header["e_shstrndx"],
        }

    def _get_section_headers(self):
        section_headers = []
        for section in self.elf.iter_sections():
            section_headers.append({
                "name": section.name,
                "type": describe_sh_type(section["sh_type"]),
                "addr": self._print_addr(section["sh_addr"]),
                "size": section["sh_size"],
            })
        return section_headers

    def _get_program_headers(self):
        program_headers = []
        for segment in self.elf.iter_segments():
            program_headers.append({
                "type": describe_p_type(segment["p_type"]),
                "addr": self._print_addr(segment["p_vaddr"]),
                "flags": describe_p_flags(segment["p_flags"]).strip(),
                "size": segment["p_memsz"],
            })
        return program_headers

    def _get_dynamic_tags(self):
        dynamic_tags = []
        for section in self.elf.iter_sections():
            if not isinstance(section, DynamicSection):
                continue
            for tag in section.iter_tags():
                dynamic_tags.append({
                    "tag": self._print_addr(
                        ENUM_D_TAG.get(tag.entry.d_tag, tag.entry.d_tag)
                    ),
                    "type": str(tag.entry.d_tag)[3:],
                    "value": self._parse_tag(tag),
                })

        return dynamic_tags

    def _get_symbol_tables(self):
        symbol_tables = []
        for section in self.elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for nsym, symbol in enumerate(section.iter_symbols()):
                symbol_tables.append({
                    "value": self._print_addr(symbol["st_value"]),
                    "type": describe_symbol_type(symbol["st_info"]["type"]),
                    "bind": describe_symbol_bind(symbol["st_info"]["bind"]),
                    "ndx_name": symbol.name,
                })
        return symbol_tables

    def _get_relocations(self):
        relocations = []
        for section in self.elf.iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            section_relocations = []
            for rel in section.iter_relocations():
                relocation = {
                    "offset": self._print_addr(rel["r_offset"]),
                    "info": self._print_addr(rel["r_info"]),
                    "type": describe_reloc_type(rel["r_info_type"], self.elf),
                    "value": "",
                    "name": ""
                }

                if rel["r_info_sym"] != 0:
                    symtable = self.elf.get_section(section["sh_link"])
                    symbol = symtable.get_symbol(rel["r_info_sym"])
                    # Some symbols have zero "st_name", so instead use
                    # the name of the section they point at
                    if symbol["st_name"] == 0:
                        symsec = self.elf.get_section(symbol["st_shndx"])
                        symbol_name = symsec.name
                    else:
                        symbol_name = symbol.name

                    relocation["value"] = self._print_addr(symbol["st_value"])
                    relocation["name"] = symbol_name

                if relocation not in section_relocations:
                    section_relocations.append(relocation)

            relocations.append({
                "name": section.name,
                "entries": section_relocations,
            })
        return relocations

    def _get_notes(self):
        notes = []
        for segment in self.elf.iter_segments():
            if not isinstance(segment, NoteSegment):
                continue
            for note in segment.iter_notes():
                notes.append({
                    "owner": note["n_name"],
                    "size": self._print_addr(note["n_descsz"]),
                    "note": describe_note(note),
                    "name": note["n_name"],
                })
        return notes

    def _print_addr(self, addr):
        fmt = "0x{0:08x}" if self.elf.elfclass == 32 else "0x{0:016x}"
        return fmt.format(addr)

    def _decode_flags(self, flags):
        description = ""
        if self.elf["e_machine"] == "EM_ARM":
            if flags & E_FLAGS.EF_ARM_HASENTRY:
                description = ", has entry point"

            version = flags & E_FLAGS.EF_ARM_EABIMASK
            if version == E_FLAGS.EF_ARM_EABI_VER5:
                description = ", Version5 EABI"
        elif self.elf["e_machine"] == "EM_MIPS":
            if flags & E_FLAGS.EF_MIPS_NOREORDER:
                description = ", noreorder"
            if flags & E_FLAGS.EF_MIPS_CPIC:
                description = ", cpic"
            if not (flags & E_FLAGS.EF_MIPS_ABI2) and not (flags & E_FLAGS.EF_MIPS_ABI_ON32):
                description = ", o32"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_1:
                description = ", mips1"

        return description

    def _parse_tag(self, tag):
        if tag.entry.d_tag == "DT_NEEDED":
            parsed = "Shared library: [%s]" % tag.needed
        elif tag.entry.d_tag == "DT_RPATH":
            parsed = "Library rpath: [%s]" % tag.rpath
        elif tag.entry.d_tag == "DT_RUNPATH":
            parsed = "Library runpath: [%s]" % tag.runpath
        elif tag.entry.d_tag == "DT_SONAME":
            parsed = "Library soname: [%s]" % tag.soname
        elif isinstance(tag.entry.d_tag, basestring) and tag.entry.d_tag.endswith(("SZ", "ENT")):
            parsed = "%i (bytes)" % tag["d_val"]
        elif isinstance(tag.entry.d_tag, basestring) and tag.entry.d_tag.endswith(("NUM", "COUNT")):
            parsed = "%i" % tag["d_val"]
        elif tag.entry.d_tag == "DT_PLTREL":
            s = describe_dyn_tag(tag.entry.d_val)
            if s.startswith("DT_"):
                s = s[3:]
            parsed = "%s" % s
        else:
            parsed = self._print_addr(tag["d_val"])

        return parsed

def _pdf_worker(filepath):
    return PdfDocument(filepath).run()

class Static(Processing):
    """Static analysis."""

    office_ext = [
        "doc", "docm", "dotm", "docx", "hwp", "ppt", "pptm", "pptx", "potm",
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

        if package == "generic" and (ext == "elf" or "ELF" in f.get_type()):
            static["elf"] = ELF(f.file_path).run()
            static["keys"] = f.get_keys()

        if package == "exe" or ext == "exe" or "PE32" in f.get_type():
            static.update(PortableExecutable(f.file_path).run())
            static["keys"] = f.get_keys()

        if package == "wsf" or ext == "wsf":
            static["wsf"] = WindowsScriptFile(f.file_path).run()

        if package in ("doc", "ppt", "xls") or ext in self.office_ext:
            static["office"] = OfficeDocument(f.file_path, self.task["id"]).run()

        if package == "pdf" or ext == "pdf":
            if f.get_content_type() == "application/pdf":
                static["pdf"] = dispatch(
                    _pdf_worker, (f.file_path,),
                    timeout=self.options.pdf_timeout
                ) or []
            else:
                static["pdf"] = []

        if package == "generic" or ext == "lnk":
            static["lnk"] = LnkShortcut(f.file_path).run()

        return static
