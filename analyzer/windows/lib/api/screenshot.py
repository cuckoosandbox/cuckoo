# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

try:
    import Image
    import ImageGrab
    import ImageChops
    HAVE_PIL = True
except:
    HAVE_PIL = False

class Screenshot:
    """Get screenshots."""

    def have_pil(self):
        """Is Python Image Library installed?
        @return: installed status.
        """
        return HAVE_PIL

    def equal(self, img1, img2):
        """Compares two screenshots.
        @param img1: screenshot to compare.
        @param img2: screenshot to compare.
        @return: equal status.
        """
        if not HAVE_PIL:
            return None

        return ImageChops.difference(img1, img2).getbbox() is None

    def take(self):
        """Take a screenshot.
        @return: screenshot or None.
        """
        if not HAVE_PIL:
            return None

        return ImageGrab.grab()