# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import select
import socket
import threading

try:
    import pycares
    HAVE_CARES = True
except:
    HAVE_CARES = False

# try:
#    import gevent, gevent.socket
#    HAVE_GEVENT = True
# except:
HAVE_GEVENT = False


# these are used by all resolvers
DNS_TIMEOUT = 5
DNS_TIMEOUT_VALUE = ""

def set_timeout(value):
    global DNS_TIMEOUT
    DNS_TIMEOUT = value

def set_timeout_value(value):
    global DNS_TIMEOUT_VALUE
    DNS_TIMEOUT_VALUE = value


# standard gethostbyname in thread
# http://code.activestate.com/recipes/473878/
def with_timeout(func, args=(), kwargs={}):
    """This function will spawn a thread and run the given function
    using the args, kwargs and return the given default value if the
    timeout_duration is exceeded.
    """
    class ResultThread(threading.Thread):
        daemon = True

        def __init__(self):
            threading.Thread.__init__(self)
            self.result, self.error = None, None

        def run(self):
            try:
                self.result = func(*args, **kwargs)
            except Exception, e:
                self.error = e

    it = ResultThread()
    it.start()
    it.join(DNS_TIMEOUT)
    if it.isAlive():
        return DNS_TIMEOUT_VALUE
    else:
        if it.error:
            raise it.error
        return it.result

def resolve_thread(name):
    return with_timeout(gethostbyname, (name,))

def gethostbyname(name):
    try:
        ip = socket.gethostbyname(name)
    except socket.gaierror:
        ip = ""
    return ip


# C-ARES (http://c-ares.haxx.se/)
def resolve_cares(name):
    # create new c-ares channel
    careschan = pycares.Channel(timeout=DNS_TIMEOUT, tries=1)

    # if we don't get a response we return the default value
    result = Resultholder()
    result.value = DNS_TIMEOUT_VALUE

    def setresult_cb(res, error):
        # ignore error and just take first result ip (randomized anyway)
        if res and res.addresses:
            result.value = res.addresses[0]

    # resolve with cb
    careschan.gethostbyname(name, socket.AF_INET, setresult_cb)

    # now do the actual work
    readfds, writefds = careschan.getsock()
    canreadfds, canwritefds, _ = select.select(readfds, writefds, [],
                                               DNS_TIMEOUT)
    for rfd in canreadfds:
        careschan.process_fd(rfd, -1)

    # if the query did not succeed, setresult was not called and we just
    # return result destroy the channel first to not leak anything
    careschan.destroy()
    return result.value

# workaround until py3 nonlocal (for c-ares and gevent)
class Resultholder:
    pass


# gevent based resolver with timeout
"""def resolve_gevent(name):
    result = resolve_gevent_real(name)
    # if it failed, do this a second time because of strange libevent behavior
    # basically sometimes the Timeout fires immediately instead of after
    # DNS_TIMEOUT
    if result == DNS_TIMEOUT_VALUE:
        result = resolve_gevent_real(name)
    return result

def resolve_gevent_real(name):
    result = DNS_TIMEOUT_VALUE
    with gevent.Timeout(DNS_TIMEOUT, False):
        try:
            result = gevent.socket.gethostbyname(name)
        except socket.gaierror:
            pass

    return result
"""

# choose resolver automatically
def resolve(name):
    if HAVE_CARES:
        return resolve_cares(name)
    # elif HAVE_GEVENT:
    #    return resolve_gevent(name)
    else:
        return resolve_thread(name)

# another alias
resolve_best = resolve
