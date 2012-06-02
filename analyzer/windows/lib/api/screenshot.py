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
    def have_pil(self):
        return HAVE_PIL

    def equal(self, img1, img2):
        if not HAVE_PIL:
            return None

        return ImageChops.difference(img1, img2).getbbox() is None

    def take(self):
        if not HAVE_PIL:
            return None

        return ImageGrab.grab()