# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.

import math
import filecmp

try:
    import ImageChops
    from PIL import Image
    HAVE_PIL = True
except:
    try:
        from PIL import ImageChops
        from PIL import Image
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

    def equal_old(self, img1, img2):
        """Compares two screenshots using Root-Mean-Square Difference (RMS).
        @param img1: screenshot to compare.
        @param img2: screenshot to compare.
        @return: equal status.
        """
        if not HAVE_PIL:
            return None
        image1 = Image.open(img1)
        image2 = Image.open(img2)
        # To get a measure of how similar two images are, we use
        # root-mean-square (RMS). If the images are exactly identical,
        # this value is zero.
        diff = ImageChops.difference(image1, image2)
        h = diff.histogram()
        sq = (value*((idx % 256)**2) for idx, value in enumerate(h))
        sum_of_squares = sum(sq)
        rms = math.sqrt(sum_of_squares/float(image1.size[0] * image2.size[1]))

        # Might need to tweak the threshold.
        return rms < 8

    def equal(self, img1, img2):
        return filecmp.cmp(img1, img2)
