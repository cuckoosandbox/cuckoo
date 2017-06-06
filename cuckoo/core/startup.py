# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
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
from cuckoo.common.objects import File
from cuckoo.core.database import (
    Database, TASK_RUNNING, TASK_FAILED_ANALYSIS, TASK_PENDING
)
from cuckoo.core.feedback import CuckooFeedbackObject
from cuckoo.core.log import init_logger
from cuckoo.core.rooter import rooter
from cuckoo.misc import cwd, version

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
        r = requests.post(
            "http://api.cuckoosandbox.org/checkversion.php",
            data={"version": version}
        )
        r.raise_for_status()
        r = r.json()
    except (requests.RequestException, ValueError) as e:
        print(red(" Error checking for the latest Cuckoo version: %s!" % e))
        return

    if not isinstance(r, dict) or r.get("error"):
        print(red(" Error checking for the latest Cuckoo version:"))
        print(yellow(" Response: %s" % r))
        return

    rc1_responses = "NEW_VERSION", "NO_UPDATES"

    # Deprecated response.
    if r.get("response") in rc1_responses and r.get("current") == "2.0-rc1":
        print(green(" You're good to go!"))
        return

    try:
        old = StrictVersion(version) < StrictVersion(r.get("current"))
    except ValueError:
        old = True

    if old:
        msg = "Cuckoo Sandbox version %s is available now." % r.get("current")
        print(red(" Outdated! ") + msg),
    else:
        print(green(" You're good to go!"))

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

def index_yara():
    """Generates index for yara signatures."""
    log.debug("Initializing Yara...")

    indexed = []
    for category in ("binaries", "urls", "memory", "scripts", "shellcode"):
        # Check if there is a directory for the given category.
        dirpath = cwd("yara", category)
        if not os.path.exists(dirpath):
            continue

        # Populate the index Yara file for this category.
        with open(cwd("yara", "index_%s.yar" % category), "wb") as f:
            for entry in os.listdir(dirpath):
                if entry.endswith((".yar", ".yara")):
                    f.write("include \"%s\"\n" % os.path.join(dirpath, entry))
                    indexed.append((category, entry))

    indexed = sorted(indexed)
    for category, entry in indexed:
        if (category, entry) == indexed[-1]:
            log.debug("\t `-- %s %s", category, entry)
        else:
            log.debug("\t |-- %s %s", category, entry)

def init_yara(index):
    """Initialize & load/compile Yara rules."""
    if index:
        index_yara()

    for category in ("binaries", "urls", "memory", "scripts", "shellcode"):
        rulepath = cwd("yara", "index_%s.yar" % category)
        if not os.path.exists(rulepath) and not index:
            raise CuckooStartupError(
                "You must run the Cuckoo daemon before being able to run "
                "this utility, as otherwise any potentially available Yara "
                "rules will not be taken into account (yes, also if you "
                "didn't configure any Yara rules)!"
            )

        try:
            File.yara_rules[category] = yara.compile(rulepath)
        except yara.Error as e:
            raise CuckooStartupError(
                "There was a syntax error in one or more Yara rules: %s" % e
            )
    return True

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
