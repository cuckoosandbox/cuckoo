# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import logging.handlers
import os
import requests
import socket
import yara

from distutils.version import StrictVersion

import cuckoo

from cuckoo.common.colors import red, green, yellow
from cuckoo.common.config import Config, config, config2
from cuckoo.common.exceptions import CuckooStartupError, CuckooFeedbackError
from cuckoo.common.files import temppath
from cuckoo.common.objects import File
from cuckoo.core.database import (
    Database, TASK_RUNNING, TASK_FAILED_ANALYSIS, TASK_PENDING
)
from cuckoo.core.extract import ExtractManager
from cuckoo.core.feedback import CuckooFeedbackObject
from cuckoo.core.log import init_logger
from cuckoo.core.plugins import RunSignatures
from cuckoo.core.rooter import rooter
from cuckoo.misc import cwd, version, getuser, mkdir

log = logging.getLogger(__name__)

def check_specific_config(filename):
    sections = Config.configuration[filename]
    for section, entries in sections.items():
        if section == "*" or section == "__star__":
            continue

        # If an enabled field is present, check it beforehand.
        if config("%s:%s:enabled" % (filename, section)) is False:
            continue

        for key, value in entries.items():
            config(
                "%s:%s:%s" % (filename, section, key),
                check=True, strict=True
            )

def check_configs():
    """Checks if config files exist.
    @raise CuckooStartupError: if config files do not exist.
    """
    configs = (
        "auxiliary", "cuckoo", "memory", "processing", "reporting", "routing",
    )

    for filename in configs:
        if not os.path.exists(cwd("conf", "%s.conf" % filename)):
            raise CuckooStartupError(
                "Config file does not exist at path: %s" %
                cwd("conf", "%s.conf" % filename)
            )

        check_specific_config(filename)

    # Also check the specific machinery handler for this instance.
    machinery = config("cuckoo:cuckoo:machinery")
    if machinery not in Config.configuration:
        raise CuckooStartupError(
            "An unknown machinery has been chosen (machinery=%s)!" % machinery
        )

    check_specific_config(machinery)

    # If Cuckoo Feedback is enabled, ensure its configuration is valid.
    feedback_enabled = (
        config("cuckoo:feedback:enabled") or
        config("reporting:feedback:enabled")
    )
    if feedback_enabled:
        try:
            CuckooFeedbackObject(
                name=config("cuckoo:feedback:name"),
                email=config("cuckoo:feedback:email"),
                company=config("cuckoo:feedback:company"),
                message="startup"
            ).validate()
        except CuckooFeedbackError as e:
            raise CuckooStartupError(
                "You have filled out the Cuckoo Feedback configuration, but "
                "there's an error in it: %s" % e
            )
    return True

def check_version():
    """Checks version of Cuckoo."""
    if not config("cuckoo:cuckoo:version_check"):
        return

    print(" Checking for updates...")

    try:
        r = requests.get(
            "https://cuckoosandbox.org/updates.json",
            params={"version": version}, timeout=6
        )
        r.raise_for_status()
        r = r.json()
    except (requests.RequestException, ValueError) as e:
        print(red(" Error checking for the latest Cuckoo version: %s!" % e))
        return

    try:
        old = StrictVersion(version) < StrictVersion(r["version"])
    except ValueError:
        old = True

    if old:
        msg = "Cuckoo Sandbox version %s is available now." % r["version"]
        print(red(" Outdated! ") + msg)
    else:
        print(green(" You're good to go!"))

    print("\n Our latest blogposts:")
    for blogpost in r["blogposts"]:
        print(" * %s, %s." % (yellow(blogpost["title"]), blogpost["date"]))
        print("   %s" % red(blogpost["oneline"]))
        print("   More at %s" % blogpost["url"])
        print("")
    return r

def init_logging(level):
    """Initializes logging."""
    logging.getLogger().setLevel(logging.DEBUG)
    init_logger("cuckoo.log", level)
    init_logger("cuckoo.json")
    init_logger("task")

def init_console_logging(level=logging.INFO):
    """Initializes logging only to console and database."""
    logging.getLogger().setLevel(logging.DEBUG)
    init_logger("console", level)
    init_logger("database")

def init_logfile(logfile):
    init_logger(logfile, logging.DEBUG)

def init_tasks():
    """Check tasks and reschedule uncompleted ones."""
    db = Database()

    log.debug("Checking for locked tasks..")
    for task in db.list_tasks(status=TASK_RUNNING):
        if config("cuckoo:cuckoo:reschedule"):
            task_id = db.reschedule(task.id)
            log.info(
                "Rescheduled task with ID %s and target %s: task #%s",
                task.id, task.target, task_id
            )
        else:
            db.set_status(task.id, TASK_FAILED_ANALYSIS)
            log.info(
                "Updated running task ID %s status to failed_analysis",
                task.id
            )

    log.debug("Checking for pending service tasks..")
    for task in db.list_tasks(status=TASK_PENDING, category="service"):
        db.set_status(task.id, TASK_FAILED_ANALYSIS)

def init_modules():
    """Initializes plugins."""
    log.debug("Imported modules...")

    categories = (
        "auxiliary", "machinery", "processing", "signatures", "reporting",
    )

    # Call the init_once() static method of each plugin/module. If an exception
    # is thrown in that initialization call, then a hard error is appropriate.
    for category in categories:
        for module in cuckoo.plugins[category]:
            module.init_once()

    for category in categories:
        log.debug("Imported \"%s\" modules:", category)

        entries = cuckoo.plugins[category]
        for entry in entries:
            if entry == entries[-1]:
                log.debug("\t `-- %s", entry.__name__)
            else:
                log.debug("\t |-- %s", entry.__name__)

    # Initialize the RunSignatures module with all available Signatures and
    # the ExtractManager with all available Extractors.
    RunSignatures.init_once()
    ExtractManager.init_once()

def init_yara():
    """Initialize & load/compile Yara rules."""
    categories = (
        "binaries", "urls", "memory", "scripts", "shellcode",
        "dumpmem", "office",
    )
    log.debug("Initializing Yara...")
    for category in categories:
        dirpath = cwd("yara", category)
        if not os.path.exists(dirpath):
            log.warning("Missing Yara directory: %s?", dirpath)

        rules, indexed = {}, []
        for dirpath, dirnames, filenames in os.walk(dirpath, followlinks=True):
            for filename in filenames:
                if not filename.endswith((".yar", ".yara")):
                    continue

                filepath = os.path.join(dirpath, filename)

                try:
                    # TODO Once Yara obtains proper Unicode filepath support we
                    # can remove this check. See also this Github issue:
                    # https://github.com/VirusTotal/yara-python/issues/48
                    assert len(str(filepath)) == len(filepath)
                except (UnicodeEncodeError, AssertionError):
                    log.warning(
                        "Can't load Yara rules at %r as Unicode filepaths are "
                        "currently not supported in combination with Yara!",
                        filepath
                    )
                    continue

                rules["rule_%s_%d" % (category, len(rules))] = filepath
                indexed.append(filename)

        # Need to define each external variable that will be used in the
        # future. Otherwise Yara will complain.
        externals = {
            "filename": "",
        }

        try:
            File.yara_rules[category] = yara.compile(
                filepaths=rules, externals=externals
            )
        except yara.Error as e:
            raise CuckooStartupError(
                "There was a syntax error in one or more Yara rules: %s" % e
            )

        # The memory.py processing module requires a yara file with all of its
        # rules embedded in it, so create this file to remain compatible.
        if category == "memory":
            f = open(cwd("stuff", "index_memory.yar"), "wb")
            for filename in sorted(indexed):
                f.write('include "%s"\n' % cwd("yara", "memory", filename))

        indexed = sorted(indexed)
        for entry in indexed:
            if (category, entry) == indexed[-1]:
                log.debug("\t `-- %s %s", category, entry)
            else:
                log.debug("\t |-- %s %s", category, entry)

    # Store the compiled Yara rules for the "dumpmem" category in
    # $CWD/stuff/ so that we may pass it along to zer0m0n during analysis.
    File.yara_rules["dumpmem"].save(cwd("stuff", "dumpmem.yarac"))

def init_binaries():
    """Inform the user about the need to periodically look for new analyzer
    binaries. These include the Windows monitor etc."""
    def throw():
        raise CuckooStartupError(
            "The binaries used for Windows analysis are updated regularly, "
            "independently from the release line. It appears that you're "
            "not up-to-date. This may happen when you've just installed the "
            "latest development version of Cuckoo or when you've updated "
            "to the latest Cuckoo. In order to get up-to-date, please run "
            "the following command: `cuckoo community`."
        )

    dirpath = cwd("monitor", "latest")

    # If "latest" is a symbolic link, check that it exists.
    if os.path.islink(dirpath):
        if not os.path.exists(dirpath):
            throw()
    # If "latest" is a file, check that it contains a legitimate hash.
    elif os.path.isfile(dirpath):
        monitor = os.path.basename(open(dirpath, "rb").read().strip())
        if not monitor or not os.path.isdir(cwd("monitor", monitor)):
            throw()
    else:
        throw()

def init_rooter():
    """If required, check if the rooter is running and if we can connect
    to it. The default configuration doesn't require the rooter to be ran."""
    required = (
        config("routing:routing:route") != "none" or
        config("routing:routing:internet") != "none" or
        config("routing:routing:drop") or
        config("routing:inetsim:enabled") or
        config("routing:tor:enabled") or
        config("routing:vpn:enabled")
    )
    if not required:
        return

    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    try:
        s.connect(config("cuckoo:cuckoo:rooter"))
    except socket.error as e:
        if e.strerror == "No such file or directory":
            raise CuckooStartupError(
                "The rooter is required but it is either not running or it "
                "has been configured to a different Unix socket path. Please "
                "refer to the documentation on working with the rooter."
            )

        if e.strerror == "Connection refused":
            raise CuckooStartupError(
                "The rooter is required but we can't connect to it as the "
                "rooter is not actually running. Please refer to the "
                "documentation on working with the rooter."
            )

        if e.strerror == "Permission denied":
            raise CuckooStartupError(
                "The rooter is required but we can't connect to it due to "
                "incorrect permissions. Did you assign it the correct group? "
                "Please refer to the documentation on working with the "
                "rooter."
            )

        raise CuckooStartupError("Unknown rooter error: %s" % e)

    # Do not forward any packets unless we have explicitly stated so.
    rooter("forward_drop")

    # Enable stateful connection tracking (but only once).
    rooter("state_disable")
    rooter("state_enable")

def init_routing():
    """Initialize and check whether the routing information is correct."""
    interfaces = set()

    # Check if all configured VPNs exist and are up and enable NAT on
    # each VPN interface.
    if config("routing:vpn:enabled"):
        for name in config("routing:vpn:vpns"):
            entry = config2("routing", name)
            if not rooter("nic_available", entry.interface):
                raise CuckooStartupError(
                    "The network interface that has been configured for "
                    "VPN %s is not available." % entry.name
                )

            if not rooter("rt_available", entry.rt_table):
                raise CuckooStartupError(
                    "The routing table that has been configured for "
                    "VPN %s is not available." % entry.name
                )

            interfaces.add((entry.rt_table, entry.interface))

    standard_routes = "none", "drop", "internet", "inetsim", "tor"

    # Check whether the default VPN exists if specified.
    if config("routing:routing:route") not in standard_routes:
        if config("routing:routing:route") not in config("routing:vpn:vpns"):
            raise CuckooStartupError(
                "The default routing target (%s) has not been configured in "
                "routing.conf, is it supposed to be a VPN?" %
                config("routing:routing:route")
            )

        if not config("routing:vpn:enabled"):
            raise CuckooStartupError(
                "The default route configured is a VPN, but VPNs have "
                "not been enabled in routing.conf."
            )

    # Check whether the dirty line exists if it has been defined.
    if config("routing:routing:internet") != "none":
        if not rooter("nic_available", config("routing:routing:internet")):
            raise CuckooStartupError(
                "The network interface that has been configured as dirty "
                "line is not available."
            )

        if not rooter("rt_available", config("routing:routing:rt_table")):
            raise CuckooStartupError(
                "The routing table that has been configured for dirty "
                "line interface is not available."
            )

        interfaces.add((
            config("routing:routing:rt_table"),
            config("routing:routing:internet")
        ))

    for rt_table, interface in interfaces:
        # Disable & enable NAT on this network interface. Disable it just
        # in case we still had the same rule from a previous run.
        rooter("disable_nat", interface)
        rooter("enable_nat", interface)

        # Populate routing table with entries from main routing table.
        if config("routing:routing:auto_rt"):
            rooter("flush_rttable", rt_table)
            rooter("init_rttable", rt_table, interface)

def ensure_tmpdir():
    """Verifies if the current user can read and create files in the
    cuckoo temporary directory (and creates it, if needed)."""
    try:
        if not os.path.isdir(temppath()):
            mkdir(temppath())
    except OSError as e:
        # Currently we only handle EACCES.
        if e.errno != errno.EACCES:
            raise

    if os.path.isdir(temppath()) and os.access(temppath(), os.R_OK | os.W_OK):
        return True

    print red(
        "Cuckoo cannot read or write files into the temporary directory '%s',"
        " please make sure the user running Cuckoo has the ability to do so. "
        "If the directory does not yet exist and the parent directory is "
        "owned by root, then please create and chown the directory with root."
        % temppath()
    )
    return False
