# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
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

        diff = ImageChops.difference(img1, img2)
        h = diff.histogram()
        sq = (value*((idx%256)**2) for idx, value in enumerate(h))
        sum_of_squares = sum(sq)
        rms = math.sqrt(sum_of_squares/float(img1.size[0] * img1.size[1]))

        return rms < 40 # Might need to tweak the threshold

    def take(self):
        """Take a screenshot.
        @return: screenshot or None.
        """
        if not HAVE_PIL:
            return None

        return ImageGrab.grab()
