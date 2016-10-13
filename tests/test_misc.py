# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import pytest
import time

from cuckoo.misc import dispatch

def test_dispatch():
    def return_value(value):
        return value

    assert dispatch(return_value, (1,)) == 1
    assert dispatch(return_value, ("foo",)) == "foo"

    def sleep2(value):
        time.sleep(2)
        return value

    assert dispatch(sleep2, (2,)) == 2
    assert dispatch(sleep2, (2,), timeout=1) is None

    with pytest.raises(RuntimeError):
        dispatch(None, args=None)

    with pytest.raises(RuntimeError):
        dispatch(None, kwargs=None)

    with pytest.raises(RuntimeError):
        dispatch(None, process=False)
