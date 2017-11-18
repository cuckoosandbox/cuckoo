# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import PIL.Image
import subprocess

from cuckoo.common.abstracts import Processing

logging.getLogger("PIL.PngImagePlugin").setLevel(level=logging.INFO)

log = logging.getLogger(__name__)

class Screenshots(Processing):
    """Screenshot file + OCR analysis."""

    def run(self):
        """Run analysis.
        @return: list of screenshots with optional OCR content.
        """
        self.key = "screenshots"
        screenshots = []
        tesseract = self.options.get("tesseract")

        if not os.path.isdir(self.shots_path):
            return

        if tesseract:
            if tesseract == "no":
                tesseract = None
            elif not os.path.exists(tesseract):
                log.error(
                    "Could not find tesseract binary, screenshot OCR aborted."
                )
                tesseract = None

        for shot_file in sorted(os.listdir(self.shots_path)):
            if not shot_file.endswith(".jpg"):
                continue

            if "_" in shot_file:
                continue

            shot_path = os.path.join(self.shots_path, shot_file)
            shot_file_name, shot_file_ext = os.path.splitext(shot_file)

            shot_file_name_resized = "%s_%s.jpg" % (shot_file_name, "small")
            shot_path_resized = os.path.join(
                self.shots_path, shot_file_name_resized
            )

            try:
                im = PIL.Image.open(shot_path)
                im.thumbnail((320, 320), PIL.Image.ANTIALIAS)
                im.save(shot_path_resized, "JPEG")
            except IOError as e:
                if "image file is truncated" in e.message:
                    continue
                raise

            shot_entry = {
                "path": shot_path,
                "ocr": "",
            }

            if tesseract:
                try:
                    args = [tesseract, shot_path, "stdout"]
                    shot_entry["ocr"] = subprocess.check_output(args)
                except subprocess.CalledProcessError as e:
                    log.warning("Error running tesseract: %s", e)

            # Append entry to list of screenshots.
            screenshots.append(shot_entry)

        return screenshots
