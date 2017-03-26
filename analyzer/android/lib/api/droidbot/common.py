# Copyright (C) 2012-2015  Diego Torres Milano
# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
def _nd(name):
    '''
    @return: Returns a named decimal regex
    '''
    return '(?P<%s>\d+)' % name

def _nh(name):
    '''
    @return: Returns a named hex regex
    '''
    return '(?P<%s>[0-9a-f]+)' % name


def _ns(name, greedy=False):
    '''
    NOTICE: this is using a non-greedy (or minimal) regex
    @type name: str
    @param name: the name used to tag the expression
    @type greedy: bool
    @param greedy: Whether the regex is greedy or not
    @return: Returns a named string regex (only non-whitespace characters allowed)
    '''
    return '(?P<%s>\S+%s)' % (name, '' if greedy else '?')


def obtainPxPy(m):
    px = int(m.group('px'))
    py = int(m.group('py'))
    return (px, py)


def obtainVxVy(m):
    wvx = int(m.group('vx'))
    wvy = int(m.group('vy'))
    return wvx, wvy


def obtainVwVh(m):
    (wvx, wvy) = obtainVxVy(m)
    wvx1 = int(m.group('vx1'))
    wvy1 = int(m.group('vy1'))
    return (wvx1 - wvx, wvy1 - wvy)
