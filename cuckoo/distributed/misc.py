# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import datetime

from cuckoo.common.utils import Singleton
from cuckoo.misc import cwd

class settings(object):
    """Settings object containing the various configurable components of
    Distributed Cuckoo."""

def init_settings():
    s = {}
    execfile(cwd("distributed", "settings.py"), s)

    for key, value in s.items():
        if key.startswith("_"):
            continue

        setattr(settings, key, value)

class StatsCache(object):
    """Used to cache values. Values are stored under a group name. This
    group name contains keys which a datetime strings rounded to a step size.
    The key can contain a given str prefix. A step size is an int representing
    an amount of minutes to which a given datetime will be rounded.

    Cache entries will be cleared after max_cached_days have passed.
    """

    __metaclass__ = Singleton
    dt_ftm = "%Y-%m-%d %H:%M:%S"
    max_cache_days = 60

    def __init__(self):
        self._init_stats()

    def update(self, name, step_size, increment_by=1, default={},
               set_value=None, set_dt=None, key_prefix=""):
        """Set or increment value for given name/group under current time
        rounded to nearest stepsize in minutes.
        @param name: Key under which (prefix)datetime keys with cache
        values will be stored
        @param step_size: size in minute (1,5,30,60 etc) to which the current
        datetime should be rounded up to.
        @param increment_by: increment existing value by this number.
        @param default: Used to store "nothing" if no data is available
        @param set_value: the value given to be stored
        @param set_dt: datetime obj to create the key with step_size
        @param key_prefix: prefix to use with given datetime obj
        """
        self._check_if_reset()

        now = datetime.datetime.now()
        # Do not cache values for future dates
        if set_dt and now <= set_dt:
            return

        # Get current datetime and round to nearest step_size
        key = self.round_nearest_step(now, step_size).strftime(self.dt_ftm)
        if name not in self.stats:
            self.stats[name] = {}

        if set_dt:
            if set_value is None:
                set_value = default

            dt_step = self.round_nearest_step(
                set_dt, step_size
            ).strftime(self.dt_ftm)

            key = "%s%s" % (key_prefix, dt_step)
            self.stats[name][key] = set_value
        else:
            if key not in self.stats[name]:
                self.stats[name][key] = 0
            self.stats[name][key] += increment_by

    def get_stat(self, name, dt, step_size, key_prefix=""):
        """Retrieve value under given name for datetime obj rounded to
        given nearest step size with key prefix if given. Returns
        None if no cached value or given dt is now"""
        self._check_if_reset()
        if name not in self.stats:
            return None

        dt = self.round_nearest_step(dt, step_size)

        # Never return a cache value for current time, since these values
        # can still change
        if dt < datetime.datetime.now():
            return self.stats[name].get("%s%s" % (
                key_prefix, dt.strftime(self.dt_ftm)
            ))
        else:
            return None

    def _init_stats(self):
        self._reset_at = datetime.datetime.now() + datetime.timedelta(
            days=self.max_cache_days
        )
        self.stats = {
            "_info": {
                "since": datetime.datetime.now()
            }
        }

    def _check_if_reset(self):
        if datetime.datetime.now() >= self._reset_at:
            del self.stats
            self._init_stats()

    def round_nearest_step(self, dt, step_size):
        """Round given datetime to nearest step size (minutes).
        16:44 with step size 15 will be 16:45 etc"""
        until_next = (step_size - (dt.minute % step_size))
        return (
            dt + datetime.timedelta(minutes=until_next)
        ).replace(second=0, microsecond=0)
