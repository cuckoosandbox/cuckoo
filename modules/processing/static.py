# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import datetime
import logging
import os
import re
import struct
import zipfile

try:
    import bs4
    HAVE_BS4 = True
except ImportError:
    HAVE_BS4 = False

try:
    import magic
    HAVE_MAGIC = True
except ImportError:
    HAVE_MAGIC = False

try:
    import pefile
    import peutils
    HAVE_PEFILE = True
except ImportError:
    HAVE_PEFILE = False

try:
    import M2Crypto
    HAVE_MCRYPTO = True
except ImportError:
    HAVE_MCRYPTO = False

try:
    import oletools.olevba
    HAVE_OLETOOLS = True
except ImportError:
    HAVE_OLETOOLS = False

try:
    import peepdf.PDFCore
    import peepdf.JSAnalysis
    HAVE_PEEPDF = True
except ImportError:
    HAVE_PEEPDF = False

try:
    import PyV8
    HAVE_PYV8 = True

    PyV8  # Fake usage.
except:
    HAVE_PYV8 = False

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.utils import convert_to_printable
from lib.cuckoo.common.utils import to_unicode
from lib.cuckoo.misc import dispatch

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
        if not HAVE_MAGIC:
            return None

        try:
            ms = magic.open(magic.MAGIC_NONE)
            ms.load()
            file_type = ms.buffer(data)
        except:
            try:
                file_type = magic.from_buffer(data)
            except Exception:
                return None
        finally:
            try:
                ms.close()
            except:
                pass

        return file_type

    def _get_peid_signatures(self):
        """Gets PEID signatures.
        @return: matched signatures or None.
        """
        try:
            sig_path = os.path.join(CUCKOO_ROOT, "data",
                                    "peutils", "UserDB.TXT")
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
            log.critical("You do not have the m2crypto library installed "
                         "preventing certificate extraction: "
                         "pip install m2crypto")
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

    def __init__(self, filepath):
        self.filepath = filepath
        self.files = {}

    def get_macros(self):
        """Get embedded Macros if this is an Office document."""
        if not HAVE_OLETOOLS:
            log.warning(
                "In order to do static analysis of Microsoft Word documents "
                "we're going to require oletools (`pip install oletools`)"
            )
            return

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

    def run(self):
        if not HAVE_PEEPDF:
            log.warning(
                "Unable to perform static PDF analysis as PeePDF is missing "
                "(install with `pip install peepdf`)"
            )
            return

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
                if obj.object.type == "stream":
                    stream = obj.object.decodedStream

                    # Is this actually Javascript code?
                    if not peepdf.JSAnalysis.isJavascript(stream):
                        continue

                    row["javascript"].append({
                        "orig_code": stream.decode("latin-1"),
                        "urls": [],
                    })
                    continue

                if obj.object.type == "dictionary":
                    for url in obj.object.urlsFound:
                        row["urls"].append(self._parse_string(url))

                    for url in obj.object.uriList:
                        row["urls"].append(self._parse_string(url))

            ret.append(row)

        return ret

class Static(Processing):
    """Static analysis."""
    PUBKEY_RE = "(-----BEGIN PUBLIC KEY-----[a-zA-Z0-9\\n\\+/]+-----END PUBLIC KEY-----)"
    PRIVKEY_RE = "(-----BEGIN RSA PRIVATE KEY-----[a-zA-Z0-9\\n\\+/]+-----END RSA PRIVATE KEY-----)"

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

        # Does the target file still exist?
        if self.task["category"] != "file" or \
                not os.path.exists(self.file_path):
            return

        package = self.task.get("package")

        if self.task["category"] == "file":
            ext = os.path.splitext(self.task["target"])[1].lstrip(".").lower()
        else:
            ext = None

        if ext == "exe" or "PE32" in File(self.file_path).get_type():
            if HAVE_PEFILE:
                static.update(PortableExecutable(self.file_path).run())
            static["keys"] = self._get_keys()

        if package == "wsf" or ext == "wsf":
            static["wsf"] = WindowsScriptFile(self.file_path).run()

        if package in ("doc", "ppt", "xls") or ext in self.office_ext:
            static["office"] = OfficeDocument(self.file_path).run()

        def pdf_worker(filepath):
            return PdfDocument(filepath).run()

        if package == "pdf" or ext == "pdf":
            timeout = int(self.options.get("pdf_timeout", 60))
            static["pdf"] = dispatch(
                pdf_worker, (self.file_path,), timeout=timeout
            )

        return static

    def _get_keys(self):
        """Get any embedded plaintext public and/or private keys."""
        buf = open(self.file_path).read()
        ret = set()
        ret.update(re.findall(self.PUBKEY_RE, buf))
        ret.update(re.findall(self.PRIVKEY_RE, buf))
        return list(ret)
