# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import time

from cuckoo.common.abstracts import Auxiliary
from cuckoo.common.config import Config
from cuckoo.core.database import Database

log = logging.getLogger(__name__)
db = Database()

class Services(Auxiliary):
    """Allows one or more additional VMs to be run next to an analysis. Either
    as global services (which are generally never rebooted) or on a
    per-analysis basis."""

    def start_service(self, service):
        """Start a VM containing one or more services."""
        # We give all services a total of 5 minutes to boot up before
        # starting the actual analysis.
        timeout = self.task.timeout or Config().timeouts.default
        timeout += 300
        tags = "service,%s" % service

        return db.add_service(timeout, self.task.owner, tags)

    def stop_service(self, task_id):
        """Stop a VM containing one or more services."""
        db.guest_set_status(task_id, "stop")

    def start(self):
        self.tasks = []

        if self.task.category == "service":
            return

        # Have to explicitly enable services.
        if not self.task.options.get("services"):
            return

        for service in self.options.get("services", "").split(","):
            service = service.strip()
            if not service:
                continue

            task_id = self.start_service(service)
            self.tasks.append((task_id, service))

            log.info("Started service %s #%d for task #%d",
                     service, task_id, self.task.id)

        # Wait until each service is either starting to run, running, or for
        # some reason stopped.
        wait_states = "starting", "running", "stopping"
        for task_id, service in self.tasks:
            while db.guest_get_status(task_id) not in wait_states:
                time.sleep(1)

        # Wait an additional timeout before starting the actual analysis.
        timeout = self.options.get("timeout")
        if isinstance(timeout, int):
            time.sleep(timeout)

    def stop(self):
        if self.task.category == "service":
            return

        for task_id, service in self.tasks:
            log.info("Stopping service %s #%d for task #%d",
                     service, task_id, self.task.id)
            self.stop_service(task_id)
