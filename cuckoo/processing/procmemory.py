# Copyright (C) 2014-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import hashlib
import logging
import os
import pefile
import re
import roach

from cuckoo.common.abstracts import Processing
from cuckoo.common.objects import File
from cuckoo.core.extract import ExtractManager

log = logging.getLogger(__name__)

class ProcessMemory(Processing):
    """Analyze process memory dumps."""
    def create_idapy(self, process):
        i = open(process["file"], "rb")
        o = open(process["file"].replace(".dmp", ".py"), "wb")

        print>>o, "from idaapi import add_segm, mem2base, autoMark, AU_CODE"
        print>>o, "from idaapi import set_processor_type, SETPROC_ALL"
        print>>o, "set_processor_type('80386r', SETPROC_ALL)"

        for idx, region in enumerate(process["regions"]):
            i.seek(region["offset"])

            if not region["protect"]:
                section = "unk_%d" % idx
                type_ = "DATA"
            elif "x" in region["protect"]:
                section = "text_%d" % idx
                type_ = "CODE"
            elif "w" in region["protect"]:
                section = "data_%d" % idx
                type_ = "DATA"
            else:
                section = "rdata_%d" % idx
                type_ = "DATA"

            print>>o, "add_segm(0, %s, %s, '%s', '%s')" % (
                region["addr"], region["end"], section, type_
            )
            print>>o, "mem2base('%s'.decode('base64'), %s)" % (
                i.read(region["size"]).encode("base64").replace("\n", ""),
                region["addr"]
            )
            if type_ == "CODE":
                print>>o, "autoMark(%s, AU_CODE)" % region["addr"]

    def _fixup_pe_header(self, pe):
        """Fixes the PE header from an in-memory representation to an
        on-disk representation."""
        for section in pe.sections:
            section.PointerToRawData = section.VirtualAddress
            section.SizeOfRawData = max(
                section.Misc_VirtualSize, section.SizeOfRawData
            )

        reloc = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) < reloc:
            return

        reloc = pe.OPTIONAL_HEADER.DATA_DIRECTORY[reloc]
        if not reloc.VirtualAddress or not reloc.Size:
            return

        # Disable relocations as those have already been applied.
        reloc.VirtualAddress = reloc.Size = 0
        pe.FILE_HEADER.Characteristics |= (
            pefile.IMAGE_CHARACTERISTICS["IMAGE_FILE_RELOCS_STRIPPED"]
        )
        if not pe.sections:
            return
        return pe.sections[0].VirtualAddress

    def dump_images(self, process, drop_dlls=False):
        """Dump executable images from this process memory dump."""
        buf = open(process["file"], "rb").read()

        images, capture, regions, end, pe = [], False, [], None, None
        for r in process["regions"]:
            off, size = r["offset"], r["size"]

            if capture:
                if int(r["end"], 16) > end:
                    images.append((pe, regions))
                    capture = False
                else:
                    regions.append(r)
                continue

            # We're going to take a couple of assumptions for granted here.
            # Namely, the PE header is fully intact, has not been tampered
            # with, and the DOS header, the NT header, and the Optional header
            # all remain in the first page/chunk of this PE file.
            if buf[off:off+2] != "MZ":
                continue

            try:
                pe = pefile.PE(data=buf[off:off+size], fast_load=True)
            except pefile.PEFormatError:
                continue

            # Enable the capture of memory regions.
            capture, regions = True, [r]
            end = int(r["addr"], 16) + pe.OPTIONAL_HEADER.SizeOfImage

        # If present, also process the last loaded executable.
        if capture and regions:
            images.append((pe, regions))

        for pe, regions in images:
            img = []

            # Skip DLLs if requested to do so (the default).
            if pe.is_dll() and not drop_dlls:
                continue

            hdrsz = self._fixup_pe_header(pe)
            if not hdrsz:
                continue

            img.append(str(pe.write())[:hdrsz])
            for idx, r in enumerate(regions):
                offset = r["offset"]
                if not idx:
                    offset += hdrsz
                img.append(buf[offset:r["offset"]+r["size"]])

            sha1 = hashlib.sha1("".join(img)).hexdigest()

            if pe.is_dll():
                filename = "%s-%s.dll_" % (process["pid"], sha1[:16])
            elif pe.is_exe():
                filename = "%s-%s.exe_" % (process["pid"], sha1[:16])
            else:
                log.warning(
                    "Unknown injected executable for pid=%s", process["pid"]
                )
                continue

            filepath = os.path.join(self.pmemory_path, filename)
            open(filepath, "wb").write("".join(img))

            yield File(filepath).get_all()

    def run(self):
        """Run analysis.
        @return: structured results.
        """
        self.key = "procmemory"
        results = []

        if os.path.exists(self.pmemory_path):
            for dmp in os.listdir(self.pmemory_path):
                if not dmp.endswith(".dmp"):
                    continue

                dump_path = os.path.join(self.pmemory_path, dmp)
                dump_file = File(dump_path)

                pid, num = map(int, re.findall("(\\d+)", dmp))

                regions = []
                for region in roach.procmem(dump_path).regions:
                    regions.append(region.to_json())

                proc = dict(
                    file=dump_path, pid=pid, num=num,
                    yara=dump_file.get_yara("memory"),
                    urls=list(dump_file.get_urls()),
                    regions=regions,
                )

                ExtractManager.for_task(self.task["id"]).peek_procmem(proc)

                if self.options.get("idapro"):
                    self.create_idapy(proc)

                if self.options.get("extract_img"):
                    proc["extracted"] = list(self.dump_images(
                        proc, self.options.get("extract_dll")
                    ))

                if self.options.get("dump_delete"):
                    try:
                        os.remove(dump_path)
                    except OSError:
                        log.error(
                            "Unable to delete memory dump file at path \"%s\"",
                            dump_path
                        )

                results.append(proc)

        results.sort(key=lambda x: (x["pid"], x["num"]))
        return results
