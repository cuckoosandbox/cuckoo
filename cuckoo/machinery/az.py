# Copyright (C) 2015-2020 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.
# in https://github.com/CheckPointSW/Cuckoo-AWS.
# Modified by the Canadian Centre for Cyber Security to support Azure.

import logging
import threading
import sys
import time
import socket
import operator
import inspect
import re

from sqlalchemy.exc import SQLAlchemyError

try:
    # Azure specific imports
    from azure.common.credentials import ServicePrincipalCredentials
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.compute.models import DiskCreateOption, VirtualMachinePriorityTypes, VirtualMachineEvictionPolicyTypes, BillingProfile
    HAVE_AZURE = True
except ImportError:
    HAVE_AZURE = False

# Cuckoo specific imports
from cuckoo.common.abstracts import Machinery
from cuckoo.common.config import config
from cuckoo.common.exceptions import CuckooMachineError, CuckooDependencyError, CuckooGuestCriticalTimeout
from cuckoo.common.constants import CUCKOO_GUEST_PORT

# Only log INFO or higher from imported python packages
logging.getLogger("adal-python").setLevel(logging.INFO)
logging.getLogger("msrest.universal_http").setLevel(logging.INFO)
logging.getLogger("msrest.service_client").setLevel(logging.INFO)
log = logging.getLogger(__name__)

# Creating the shared thread variables
# Variable representing how many win7 machines are currently being created
number_of_win7_machines_being_created = 0
# Variable representing how many win10 machines are currently being created
number_of_win10_machines_being_created = 0
# Variable representing how many ub1804 machines are currently being created
number_of_ub1804_machines_being_created = 0
# Variable representing how many machines have been created
dynamic_machines_sequence = 0
# Variable containing names of NICs to delete
nics_to_delete = set()
# Variable containing names of disks to delete
disks_to_delete = set()

api_call_counts = {}


class Azure(Machinery):
    """Virtualization layer for Azure."""

    # machine states.
    PENDING = "pending"
    STOPPING = "stopping"
    RUNNING = "running"
    POWEROFF = "poweroff"
    DELETING = "deleting"
    ABORTED = "failed"
    ERROR = "machete"
    SUCCEEDED = "Succeeded"

    # machine tag that indicates autoscaling.
    AUTOSCALE_CUCKOO = "AUTOSCALE_CUCKOO"

    # Resource Keys
    NIC_KEY = "nic"
    DISK_KEY = "disk"

    # Resource name formats
    NIC_NAME_FORMAT = "nic-01-%s"
    DISK_NAME_FORMAT = "osdisk-%s"
    MACHINE_NAME_FORMAT = "cuckoo-%s-%03d-%s"

    # Operating System Tags
    WINDOWS_7 = "win7"
    WINDOWS_10 = "win10"
    UBUNTU_1804 = "ub1804"
    VALID_OS_TAGS = [WINDOWS_7, WINDOWS_10, UBUNTU_1804]

    # Peak Throughput which will be used to regulate how many
    # times delete_leftover_resources is called.
    peak_throughput = 50

    # Arbitrary value for very large JSON results.
    # Relative to Python environment of machine.
    sys.setrecursionlimit(10000)

    def _initialize(self, module_name):
        """
        Overloading abstracts.py:_initialize()
        Initializing machine parameters.
        @param module_name: module name, currently not used be required
        @raise CuckooDependencyError: if there is a problem with the dependencies call
        """
        if not HAVE_AZURE:
            raise CuckooDependencyError("Unable to import Azure packages")

        # Setting the class attributes
        self.azure_machines = {}
        # TODO: use a Queue instead of a list for machine_queue?
        self.machine_queue = []
        self.dynamic_machines_count = 0
        self.initializing = True
        self.dynamic_machines_limit = self.options.az.dynamic_machines_limit
        self.running_machines_gap = float(self.options.az.running_machines_gap/100.0)
        self.environment = self.options.az.environment

        # Resource name regexes
        regex_or = "(" + Azure.WINDOWS_7 + "|" + Azure.WINDOWS_10 + "|" + Azure.UBUNTU_1804 + ")"
        self.machine_name_regex = Azure.MACHINE_NAME_FORMAT.replace("%03d", "[0-9]{3,}") % (self.environment, regex_or)
        self.nic_name_regex = Azure.NIC_NAME_FORMAT % self.machine_name_regex
        self.disk_name_regex = Azure.DISK_NAME_FORMAT % self.machine_name_regex

        # Starting the thread that sets API clients periodically
        self._thr_refresh_clients()

        # Starting the threads that deletes leftover resources and ensures pools are topped up... periodically
        self._thr_delete_leftover_resources()
        self._thr_top_up_pools()

    def _get_credentials(self):
        """
        Used to instantiate the Azure ServicePrincipalCredentials object.
        @return: an Azure ServicePrincipalCredentials object
        """

        # Instantiates the ServicePrincipalCredentials object using
        # Azure client ID, secret and Azure tenant ID
        credentials = ServicePrincipalCredentials(
            client_id=self.options.az.client_id,
            secret=self.options.az.secret,
            tenant=self.options.az.tenant
        )
        return credentials

    def _thr_refresh_clients(self):
        """
        A thread on a 30 minute timer that refreshes the network
        and compute clients using an updated ServicePrincipalCredentials
        object.
        """
        log.debug(
            "Connecting to Azure for the region '%s'.",
            self.options.az.region_name
        )

        # Getting an updated ServicePrincipalCredentials
        credentials = self._get_credentials()

        # Instantiates an Azure NetworkManagementClient using
        # ServicePrincipalCredentials and subscription ID
        self.network_client = NetworkManagementClient(
            credentials,
            self.options.az.subscription_id
        )

        # Instantiates an Azure ComputeManagementClient using
        # ServicePrincipalCredentials and subscription ID
        self.compute_client = ComputeManagementClient(
            credentials,
            self.options.az.subscription_id
        )

        # Refresh clients every half hour
        threading.Timer(1800, self._thr_refresh_clients).start()

    def _thr_delete_leftover_resources(self):
        """
        A thread on a 5 minute timer that deletes the leftover NICs and disks.
        This way we do not have to wait for a new task to trigger the deletion of
        leftover resources
        """
        log.debug("Cleaning up leftover resources...")
        self._delete_leftover_resources()

        # Starting the thread that deletes leftover resources periodically
        threading.Timer(300, self._thr_delete_leftover_resources).start()

    def _thr_top_up_pools(self):
        """
        A thread on a 1 minute timer that ensures the correct amount of machines are available.
        This way we do not have to wait for a new task to trigger the creation of machines
        in case machines have been deallocated and then deleted by the _thr_delete_leftover_resources poller.
        Note that no REST API calls are used in this method if the pools are topped up.
        """
        log.debug("Ensuring machine pools are topped up...")
        if getattr(self, "snap_ids", None):
            for snap_id in self.snap_ids:
                self._thr_create_machines(snap_id)

        # Starting the thread that tops up the pools periodically
        threading.Timer(60, self._thr_top_up_pools).start()

    def _initialize_check(self):
        """
        Overloading abstracts.py:_initialize_check()
        Setting up the Azure resource group by doing the following:
        - Cleaning up auto-scaled machines from previous Cuckoo runs
        - Cleaning up resources related to those machines
        - Create the required amount of machines as specified
        in az.conf
        """

        # Retrieving the subnet ID where we will be creating victim machines,
        # using the Azure resource group, virtual network and subnet name
        self.subnet_id = _azure_api_call(
            self.options.az.group,
            self.options.az.vnet,
            self.options.az.cuckoo_subnet,
            operation=self.network_client.subnets.get,
        ).id  # note the id attribute here

        # Retrieving all virtual machines in the Azure resource group
        machines = _azure_api_call(
            self.options.az.group,
            operation=self.compute_client.virtual_machines.list
        )

        # Retrieving all NICs, using the resource group
        nics = _azure_api_call(
            self.options.az.group,
            operation=self.network_client.network_interfaces.list
        )

        # Retrieving all disks, using the resource group
        disks = _azure_api_call(
            self.options.az.group,
            operation=self.compute_client.disks.list_by_resource_group
        )

        # Check if old nics from previous Cuckoo runs...
        for nic in nics:
            self._add_resource_to_delete_set(self.NIC_KEY, nic.name)

        # Check if old disks from previous Cuckoo runs...
        for disk in disks:
            self._add_resource_to_delete_set(self.DISK_KEY, disk.name)

        # Cleaning up auto-scaled machines from previous Cuckoo runs...
        # Check if any machines in Azure resource group are auto-scaled
        # (created by this az.py program), and if so delete them
        # TODO: Instead of putting the environment in the machine name, although this is good for identification, it may be cleaner to tag the machine with the environment instead?
        for machine in machines:
            self._delete_auto_scaled_machine(machine.tags, machine.name)

        # Allowing multiple snapshots to be used when creating machines, such as a Windows 7 and a Windows 10
        self.snap_ids = []
        # TODO: Consider renaming guest_snapshot to guest_snapshots or creating a separate config value to represent when multiple snapshots are used
        for snapshot in self.options.az.guest_snapshot:
            # Retrieving snapshots in the Azure resource group by name
            snapshot_resource = _azure_api_call(
                self.options.az.group,
                snapshot,
                operation=self.compute_client.snapshots.get
            )
            self.snap_ids.append(snapshot_resource.id)

        log.info("Deleting leftover network interface cards, managed disks " +
                 "and failed machines.")
        # Azure resource garbage collection is not inherited, as in when you delete an machine,
        # you have to delete the machine's NIC and disk separately.
        # This method cleans up resources related to those machines.
        self._delete_leftover_resources()

        # This section here creates separate machine pools for each snapshot in parallel,
        # to make system startup time faster
        create_machines_per_snapshot_threads = []
        for snap_id in self.snap_ids:
            thr = threading.Thread(target=self._thr_create_machines, args=(snap_id,))
            create_machines_per_snapshot_threads.append(thr)
            thr.start()

        # Wait for the threads to finish before continuing
        for thr in create_machines_per_snapshot_threads:
            thr.join()

        # The system is now no longer in the initializing phase.
        self.initializing = False

    def _is_auto_scaled(self, machine_tags):
        """
        Checks if the machine tags contain a tag that indicates that it was created as
        a result of autoscaling.
        @param machine_tags: machine tags object
        @return: Boolean indicating if the machine tags contain an auto-scaled tag
        """
        if machine_tags and machine_tags.get(self.AUTOSCALE_CUCKOO) == "True":
            return True
        return False

    def _thr_create_machines(self, snap_id):
        """
        Allocate new machines
        Based on the "running_machines_gap" in az.conf, ensure that there are x machines to be
        created if there are less available machines than the running_machines_gap.
        @param snap_id: the id of the snapshot to use for creating machines
        @return: Ends method call
        """
        global number_of_win7_machines_being_created
        global number_of_win10_machines_being_created
        global number_of_ub1804_machines_being_created

        # We are getting a list of all available (unlocked) machines
        available_machines = self.db.get_available_machines()

        # Getting details of the image based on snapshot ID
        tag, os_type, platform = _get_image_details(snap_id)

        # The number of relevant available machines are those from the available list that
        # have the correct tag in their name
        relevant_available_machines = len([machine for machine in available_machines if tag in machine.label])

        # Getting all tasks in the queue
        tasks = self.db.list_tasks(status=Azure.PENDING)

        # The task queue that will be used to prepare machines will be relative to the virtual
        # machine tag that is targeted in the task (win7, win10, etc)
        relevant_task_queue = 0
        for task in tasks:
            for t in task.tags:
                if t.name == tag:
                    relevant_task_queue += 1

        # If there are no relevant tasks in the queue, create the bare minimum pool size
        if relevant_task_queue == 0:
            relevant_task_queue = self.options.az.initial_pool_size

        # We want a minimum of X relevant machines * running_machines_gap% running at rest
        number_of_relevant_available_machines_required = int(round(relevant_task_queue*self.running_machines_gap)) - relevant_available_machines

        # Based on the tag related to the snapshot id, we are using the global count of number of
        # relevant machines currently being created to factor into our calculations for how many machines to create
        if tag == self.WINDOWS_10:
            number_of_relevant_machines_being_created = number_of_win10_machines_being_created
        elif tag == self.UBUNTU_1804:
            number_of_relevant_machines_being_created = number_of_ub1804_machines_being_created
        else:
            number_of_relevant_machines_being_created = number_of_win7_machines_being_created

        # No more machines are required if they are currently being spun up
        if number_of_relevant_machines_being_created >= number_of_relevant_available_machines_required:
            return

        number_of_machines_to_create = number_of_relevant_available_machines_required - number_of_relevant_machines_being_created

        log.debug(
            "Creating machines for snapshot: %s. Need %d available machines; Machines being created: %d; Machines to create: %d;",
            snap_id,
            number_of_relevant_available_machines_required,
            number_of_relevant_machines_being_created,
            number_of_machines_to_create,
        )

        # This will house the threads that create machines, only really used in system startup
        threads = []

        for machine_to_be_created in range(number_of_machines_to_create):
            # self.machines() returns all machines, locked or unlocked, in DB
            if len(self.machines()) >= self.dynamic_machines_limit:
                log.debug(
                    "Reached dynamic machines limit - %d machines.",
                    self.dynamic_machines_limit
                )
                break
            else:
                # Using threads to create machines in parallel.
                thr = threading.Thread(target=self._thr_allocate_new_machine, args=(snap_id,))
                threads.append(thr)
                thr.start()

        # Waiting for all machines to finish being created,
        # depending on the system state.
        if self.initializing:
            for thr in threads:
                thr.join()

    def _thr_allocate_new_machine(self, snap_id):
        """
        Creating new Azure machine.
        The process is as follows:
        - Create network interface card for subnet
        - Create disk using snapshot
        - Create machine with network interface card and disk
        - Add machine to database
        @param snap_id: the id of the snapshot to use for creating machines
        @raise CuckooGuestCriticalTimeout: if there is a problem with
        connecting to the guest
        @return: Ends method call
        """
        # Read configuration file.
        machinery_options = self.options.az

        global dynamic_machines_sequence

        # Getting details of the image based on snapshot ID
        tag, os_type, platform = _get_image_details(snap_id)

        # Depending on the tag, increment the global count of a certain type
        # of machine being created
        _resize_machines_being_created(tag, "+")

        # If configured, use specific network interface,
        # resultserver_ip for this machine, else use the default value.
        interface = machinery_options.get(
            "interface",
            machinery_options.interface
        )
        resultserver_ip = machinery_options.get(
            "resultserver_ip",
            config("cuckoo:resultserver:ip")
        )

        if machinery_options.resultserver_port:
            resultserver_port = machinery_options.resultserver_port
        else:
            # The ResultServer port might have been dynamically changed,
            # get it from the ResultServer singleton. Also avoid import
            # recursion issues by importing ResultServer here.
            from cuckoo.core.resultserver import ResultServer
            resultserver_port = ResultServer().port

        # This value will be used for naming machines in a unique way
        # TODO: find a better way to name machines uniquely
        dynamic_machines_sequence += 1

        new_machine_name = self.MACHINE_NAME_FORMAT % (self.environment, dynamic_machines_sequence, tag)

        # Avoiding collision on machine name if machine is still deleting.
        # TODO: this is only applicable to instances, but what about NICs and disks?
        machine_names = self._list()
        collision_exists = True  # Assuming True until proven otherwise
        while collision_exists:
            nic_name = self.NIC_NAME_FORMAT % new_machine_name
            disk_name = self.DISK_NAME_FORMAT % new_machine_name
            if nic_name in nics_to_delete or disk_name in disks_to_delete or new_machine_name in machine_names:
                dynamic_machines_sequence = dynamic_machines_sequence + 1
                new_machine_name = self.MACHINE_NAME_FORMAT % (self.environment, dynamic_machines_sequence, tag)
            else:
                collision_exists = False

        # Creating the network interface card that will be used for new machine
        new_nic_id, new_nic_ip = self._create_nic(new_machine_name, resultserver_ip)
        if new_nic_id == "SubnetIsFull":
            _resize_machines_being_created(tag, "-")
            # Bail! We cannot add any more NICs to this subnet... for now
            return

        if not new_nic_id or not new_nic_ip:
            _resize_machines_being_created(tag, "-")
            # Bail!
            log.debug("Failed to create NIC. Look for a CuckooMachineError that may indicate why this happened.")
            # TODO: Handle this error better
            return

        # If all has gone well so far, create the disk that will be used for new machine
        new_disk_id = self._create_disk_from_snapshot(new_machine_name, snap_id)

        if not new_disk_id:
            _resize_machines_being_created(tag, "-")
            log.debug("Failed to create disk. Look for a CuckooMachineError that may indicate why this happened.")
            # TODO: Handle this error better
            return

        # This time will be used for debugging. From experience, a Windows 10 machine is created in around
        # 160s and Windows 7 in 220s once the NIC and the disk are created
        machine_creation_time = time.time()

        # Create Azure machine with new NIC and disk, tagging as auto-scaled.
        new_machine = self._create_machine(
            nic_id=new_nic_id,
            tags={"Name": new_machine_name, self.AUTOSCALE_CUCKOO: True},
            platform=platform,
            disk_id=new_disk_id
        )

        # There are occasions where Azure fails to create an machine.
        # When this happens, just mark the NIC for deletion and move on
        if new_machine is None:
            _resize_machines_being_created(tag, "-")
            log.debug("Failed to create machine. Look for a CuckooMachineError that may indicate why this happened.")
            new_nic_name = self.NIC_NAME_FORMAT % new_machine_name
            self._add_resource_to_delete_set(self.NIC_KEY, new_nic_name)
            # TODO: Handle this error better
            return

        # This list will be used for acquiring machines, you'll see, you'll see
        # TODO: use a Queue instead of a list?
        self.machine_queue.append(new_machine_name)

        # A dict that holds machine name: machine details key value pairs
        self.azure_machines[new_machine_name] = new_machine

        # Sets "new_machine" object in configuration object to
        # avoid raising an exception.
        setattr(self.options, new_machine_name, {})

        # Add the os type to the tags
        tags = os_type + ", " + machinery_options.tags

        # Add machine to DB.
        # What is the point of name vs label?
        self.db.add_machine(
            name=new_machine_name,
            label=new_machine_name,
            ip=new_nic_ip,
            platform=platform,
            options=machinery_options.options,
            tags=tags,
            interface=interface,
            snapshot=machinery_options.guest_snapshot,
            resultserver_ip=resultserver_ip,
            resultserver_port=resultserver_port
        )
        # When we aren't initializing the system, the machine will immediately become available in DB
        # When we are initializing, we're going to wait for the machine to be have the agent all set up
        if self.initializing:
            # Majority of this code is copied from cuckoo/core/guest.py:GuestManager.wait_available()
            end = time.time() + config("cuckoo:timeouts:vm_state")
            while True:
                try:
                    socket.create_connection((new_nic_ip, CUCKOO_GUEST_PORT), 1).close()
                    # We did it!
                    break
                except socket.timeout:
                    log.debug("%s: Initializing...", new_machine_name)
                except socket.error:
                    log.debug("%s: Initializing...", new_machine_name)
                time.sleep(10)

                if time.time() > end:
                    # We didn't do it :(
                    raise CuckooGuestCriticalTimeout(
                        "Machine %s: the guest initialization hit the critical "
                        "timeout, analysis aborted." % new_machine_name
                    )
            log.debug("Machine %s was created and available in %9.3fs", new_machine_name, time.time() - machine_creation_time)

        # Depending on the tag, decrement the global count of a certain type
        # of machine being created
        _resize_machines_being_created(tag, "-")

    def availables(self, tags=None):
        """
        Overloading abstracts.py:availables() to utilize relevancy via tags.
        @return: number of available machines that are relevant. Note that we break after 1
        because that is all scheduler wants, a 1 or a 0
        @raise: CuckooMachineError
        """
        # This happens at the start() of scheduler
        if not tags:
            return self.db.count_machines_available()

        # We are getting a list of all available (unlocked) machines
        available_machines = self.db.get_available_machines()
        if type(tags) == list and len(tags) > 0 and tags[0] in Azure.VALID_OS_TAGS:
            requested_type = tags[0]
        else:
            requested_type = None

        # If the requested type was not passed in via tag after start(), which it must always be, do:
        if not requested_type:
            raise CuckooMachineError("The tags %s passed in to the overloaded availables() method were not valid, "
                                     "and therefore a relevant machine cannot be deemed available." % tags)

        # The number of relevant available machines are those from the available list that
        # have the correct tag in their name
        relevant_available_machines = [machine.label for machine in available_machines if requested_type in machine.label]

        # We only care about the Azure machines that are relevant and "available" according to the database
        # Now we will confirm how available they really are
        for machine in relevant_available_machines:
            if self._status(machine) == Azure.RUNNING:
                # As long as one relevant machine is running and available, we're good
                return 1
        # If no relevant machines are running or available, tell scheduler is chill
        return 0

    def acquire(self, machine_id=None, platform=None, tags=None):
        """
        Overloading abstracts.py:acquire() to utilize the auto-scale option
        as well as a FIFO queue (list) for machines.
        @param machine_id: the name of the machine to be acquired
        @param platform: the platform of the machine's operating system to be acquired
        @param tags: any tags that are associated with the machine to be acquired
        @return: dict representing machine object from DB
        """
        # This will be used to indicate what type of machine the user wants to acquire
        requested_type = None

        # Depending on setup, tags could be a list or a string. If tags is a list, do the following:
        if type(tags) == list and len(tags) > 0:
            requested_type = tags[0]
        elif type(tags) == list and len(tags) == 0:
            requested_type = "unknown_guest_image"

        # If user requests snap_id that doesn't exist, return first snap id
        requested_snap_id = next((snap_id for snap_id in self.snap_ids if requested_type in snap_id), self.snap_ids[0])
        if self.machine_queue:
            # Assume no machines are ready until proven wrong
            no_relevant_available_machines = True
            while no_relevant_available_machines:
                first_index_of_relevant_machine = next((x for x, val in enumerate(self.machine_queue) if requested_type in val), None)
                # If there are no relevant machines available based on what the user wants, return and wait.
                # We should give the people what they want.
                if first_index_of_relevant_machine is None:
                    return None
                machine_id = self.machine_queue.pop(first_index_of_relevant_machine)
                # Since this is the step right before we assign a task to a machine,
                # we should get the most up-to-date status of the machine
                machine_status = self._status(machine_id)
                # Check to see if machine is not running. Since we are using Azure Spot VMs, there is a chance it could be deallocated without us knowing.
                if not machine_status == Azure.RUNNING:
                    log.warning("Machine %s had status %s when an attempt was made to acquire it." % (machine_id, machine_status))
                    # Delete it and create another
                    self._delete_machine(machine_id)
                    self._thr_create_machines(requested_snap_id)
                    # Look for another relevant available machine in the queue
                    continue
                # If we made it here, then there is an available machine of the requested type
                no_relevant_available_machines = False

        # We are machine_id or bust
        base_class_return_value = super(Azure, self).acquire(
            machine_id=machine_id,
            platform=None,
            tags=None
        )
        # This way, the scheduler will sleep and try again
        if not base_class_return_value:
            return None

        # This should only be called intermittently when peak throughput is occurring.
        # because it has the tendency to use a ton of API calls and can hit the API rate limit
        greater_than_peak_throughput = len(self.db.list_machines(locked=True)) > self.peak_throughput
        every_x_tasks = self.db.count_tasks() % self.peak_throughput == 0
        if greater_than_peak_throughput and every_x_tasks:
            self._delete_leftover_resources()
        elif greater_than_peak_throughput and not every_x_tasks:
            pass
        else:
            self._delete_leftover_resources()

        self._thr_create_machines(requested_snap_id)
        return base_class_return_value

    def _status(self, label):
        """
        Gets current status of a machine.
        @param label: virtual machine label.
        @return: machine state string.
        """
        # Get the machine details for a machine given the resource group and label
        machine_details = _azure_api_call(
            self.options.az.group,
            label,
            operation=self.compute_client.virtual_machines.instance_view
        )

        state = None
        for status in machine_details.statuses:
            # Ideally, we're looking for the PowerState status.
            if "PowerState" in status.code:
                state = status.code
                break
            # If the PowerState status doesn't exist, then the machine is
            # deleting, or has failed.
            elif "ProvisioningState" in status.code:
                state = status.code
            else:
                state = "Unknown"

        if state == "PowerState/running":
            status = Azure.RUNNING
        elif state in ["PowerState/stopped", "PowerState/deallocated"]:
            status = Azure.POWEROFF
        elif state == "PowerState/starting":
            status = Azure.PENDING
        elif state in ["PowerState/stopping", "PowerState/deallocating"]:
            status = Azure.STOPPING
        elif state == "ProvisioningState/deleting":
            status = Azure.DELETING
        elif state == "ProvisioningState/failed/InternalOperationError":
            status = Azure.ABORTED
        else:
            status = Azure.ERROR
        return status

    # We have to "implement" this
    def start(self, label, task):
        pass

    def stop(self, label=None):
        """
        If the machine is an auto-scaled machine,
        then terminate it.
        @param label: virtual machine label
        @return: End method call
        """
        if not label:
            return
        self._delete_auto_scaled_machine(self.azure_machines[label].tags, label)

    # This method is only used for testing currently
    def _list(self):
        """
        Retrieves all virtual machines in resource group.
        @return: A list of all machine names within resource group
        """
        machines = _azure_api_call(
            self.options.az.group,
            operation=self.compute_client.virtual_machines.list
        )

        # TODO: only add the machines to the list that have the AUTOSCALED tag
        return [machine.name for machine in machines]

    def _create_nic(self, computer_name, dns_server):
        """
        Used to create the Azure network interface card.
        @param computer_name: name of machine that NIC is going to be attached to
        @param dns_server: name of server that DNS resolution will take place
        @return: a network interface card object ID string, the IP of the NIC string
        @raise CuckooMachineError: if there is a problem with the Azure call
        """
        # Setting up the NIC details
        nic_setup = {
            "location": self.options.az.region_name,
            "ip_configurations": [{
                "name": "myIPConfig",
                "subnet": {
                    "id": self.subnet_id
                }
            }],
            "dns_settings": {
                "dns_servers": [dns_server]
            }
        }
        # Setting up the name of the NIC
        new_nic_name = self.NIC_NAME_FORMAT % computer_name
        try:
            # Async call to create a network interface card using the
            # resource group, the name of the NIC and the details of
            # to-be-created NIC
            async_nic_creation = _azure_api_call(
                self.options.az.group,
                new_nic_name,
                nic_setup,
                operation=self.network_client.network_interfaces.create_or_update
            )
        except CuckooMachineError as exc:
            # If the exception contains the term SubnetIsFull, this is an edge
            # case where we do not raise the CuckooMachineError
            if "SubnetIsFull" in exc:
                return "SubnetIsFull", None
            else:
                raise
        async_nic_creation.wait()
        nic = async_nic_creation.result()

        nic_ip = None
        if nic:
            nic_ip = nic.ip_configurations[0].private_ip_address

        return nic.id, nic_ip

    def _create_disk_from_snapshot(self, new_computer_name, snap_id):
        """
        Uses a snapshot in the resource group to create a managed OS disk.
        :param new_computer_name: String indicating the name of the machine to be created
        :param snap_id: String indicating the ID of the snapshot
        :return: an Azure Managed OS Disk object ID string
        """
        # Setting up the disk details
        disk_setup = {
            "location": self.options.az.region_name,
            "creation_data": {
                "create_option": DiskCreateOption.copy,
                "source_uri": snap_id
            }
        }
        # Setting up the name of the disk
        new_disk_name = self.DISK_NAME_FORMAT % new_computer_name
        # Async call to create a disk using the
        # resource group, the name of the disk and the details of
        # to-be-created disk
        async_disk_creation = _azure_api_call(
            self.options.az.group,
            new_disk_name,
            disk_setup,
            operation=self.compute_client.disks.create_or_update
        )
        async_disk_creation.wait()
        disk = async_disk_creation.result()
        return disk.id

    def _create_machine(self, nic_id=None, tags=None, platform=None, disk_id=None):
        """
        Creating a new machine.
        @param nic_id: NIC ID of the NIC to be attached to new machine
        @param tags: tags to attach to machine
        @param platform: general platform type (windows, linux)
        @param disk_id: disk ID of the disk to be attached to new machine
        @return: the new machine dict
        """
        computer_name = tags["Name"]
        # Setting up how disk will be attached to machine
        os_disk = {
            "create_option": "Attach",
            "managed_disk": {
                "id": disk_id,
                "storage_account_type": self.options.az.storage_account_type
            },
            "osType": platform
        }
        # Setting up machine details
        machine_setup = {
            "location": self.options.az.region_name,
            "tags": tags,
            "properties": {
                "hardwareProfile": {
                    "vmSize": self.options.az.instance_type
                },
                "storageProfile": {
                    "osDisk": os_disk
                }
            },
            "networkProfile": {
                "networkInterfaces": [{
                    "id": nic_id,
                    "properties": {"primary": True}
                }]
            },
            # Note: The following key value pairs are for Azure spot instances
            "priority": VirtualMachinePriorityTypes.spot,
            "eviction_policy": VirtualMachineEvictionPolicyTypes.deallocate,
            # Note: This value may change depending on your needs.
            "billing_profile": BillingProfile(max_price=float(-1))
        }
        # Async call to create a new machine, using the resource group,
        # the computer name, and the machine details
        async_machine_creation = _azure_api_call(
            self.options.az.group,
            computer_name,
            machine_setup,
            operation=self.compute_client.virtual_machines.create_or_update
        )

        # Wait for asynchronous call to finish, then return machine details.
        new_machine = async_machine_creation.result()
        return new_machine

    def _delete_auto_scaled_machine(self, machine_tags, machine_name):
        """
        Check if machine is auto-scaled (created by this az.py program),
        then check if the detonation environment
        is found in the machine name. If both criteria are met, delete machine
        @param machine_tags: the tags of an Azure machine
        @param machine_name: the name of an Azure machine
        """
        if self._is_auto_scaled(machine_tags) and self.environment in machine_name:
            self._delete_machine(machine_name)

    def _delete_machine(self, machine_name):
        """
        Deletes an machine by marking the machine's NIC and disk for deletion,
        and then deleting the machine
        :param machine_name: String indicating the name of the machine to be deleted
        """
        # Delete the machine name from machine queue. Note that this will only be the case post-initialization
        if machine_name in self.machine_queue:
            self.machine_queue.remove(machine_name)
        # Adding the names of the machine's associated resources to delete sets
        nic_name = self.NIC_NAME_FORMAT % machine_name
        self._add_resource_to_delete_set(self.NIC_KEY, nic_name)
        disk_name = self.DISK_NAME_FORMAT % machine_name
        self._add_resource_to_delete_set(self.DISK_KEY, disk_name)

        # Deletes a machine, using the resource group and the machine name
        _azure_api_call(
            self.options.az.group,
            machine_name,
            operation=self.compute_client.virtual_machines.delete
        )

        # If the state of the system is past being initialized,
        # then delete the machine entry from the DB. Otherwise, it wouldn't be in the DB.
        if not self.initializing:
            self._delete_machine_from_db(machine_name)

    def _delete_machine_from_db(self, label):
        """
        Implementing machine deletion from Cuckoo's database.
        This was not implemented in database.py, so implemented here in the machinery
        TODO: move this method to database.py
        @param label: the machine label
        @return: End method call
        """
        session = self.db.Session()
        try:
            from cuckoo.core.database import Machine
            machine = session.query(Machine).filter_by(label=label).first()
            if machine:
                session.delete(machine)
                session.commit()
        except SQLAlchemyError as exc:
            log.debug("Database error removing machine: '%s'.", exc)
            session.rollback()
            return
        finally:
            session.close()

    def _delete_leftover_resources(self):
        """
        Used to clean up the resources that aren't cleaned up when a machine is
        deleted.
        """
        global nics_to_delete
        global disks_to_delete

        # Lists NICs, using the resource group
        paged_nics = _azure_api_call(
            self.options.az.group,
            operation=self.network_client.network_interfaces.list
        )
        # We only want the nics that are to be deleted
        nics = [nic for nic in paged_nics]
        for nic in nics[:]:
            if nic.name not in nics_to_delete:
                nics.remove(nic)

        # Lists disks, using the resource group
        paged_disks = _azure_api_call(
            self.options.az.group,
            operation=self.compute_client.disks.list_by_resource_group
        )
        # We only want the disks that are to be deleted
        disks = [disk for disk in paged_disks]
        for disk in disks[:]:
            if disk.name not in disks_to_delete:
                disks.remove(disk)

        # Lists machines, using the resource group
        machines = _azure_api_call(
            self.options.az.group,
            operation=self.compute_client.virtual_machines.list
        )

        # Create three child threads, one for deleting NICs, one for deleting disks,
        # and one for deleting machines
        nics_thr = threading.Thread(target=self._thr_delete_nics, args=(nics,))
        disks_thr = threading.Thread(target=self._thr_delete_disks, args=(disks,))
        machines_thr = threading.Thread(target=self._thr_delete_machines, args=(machines,))

        # Start 'em up!
        nics_thr.start()
        disks_thr.start()
        machines_thr.start()

    def _thr_delete_nics(self, nics):
        """
        Used to delete leftover NICs
        @param nics: a list of network interface cards
        """
        global nics_to_delete

        if self.initializing:
            threads = []
        # Iterate over all network interface cards to check if any are not
        # associated to a machine.
        for nic in nics:

            # Three indicators that a NIC is detached from a machine
            nic_is_detached = nic.virtual_machine is None and \
                              nic.primary is None and \
                              nic.provisioning_state == Azure.SUCCEEDED

            if nic_is_detached:
                # Async call to delete NIC using the resource group and the NIC name
                async_delete_nic = _azure_api_call(
                    self.options.az.group,
                    nic.name,
                    operation=self.network_client.network_interfaces.delete
                )
                nics_to_delete.discard(nic.name)
                # only wait for async call to be done if we are initializing, but do so in parallel
                # The reason we wait is because...?
                # TODO: why did I do this?
                if self.initializing:
                    thr = threading.Thread(target=async_delete_nic.wait)
                    threads.append(thr)
                    thr.start()

        # Need to wait for each network interface card to delete
        # during initialization.
        if self.initializing:
            for thr in threads:
                thr.join()

    def _thr_delete_disks(self, disks):
        """
        Used to delete leftover disks
        @param disks: a list of disks
        """
        global disks_to_delete
        # Iterate over all OS disks to check if any are not associated to a machine.
        for disk in disks:
            # If the disk is unattached, then it can be assumed that the disk can be deleted.
            # TODO: is this the best way to confirm if a disk can be deleted?
            if disk.disk_state == "Unattached":
                # Async call to delete NIC using the resource group and the disk name
                _azure_api_call(
                    self.options.az.group,
                    disk.name,
                    operation=self.compute_client.disks.delete
                )
                disks_to_delete.discard(disk.name)

    def _thr_delete_machines(self, machines):
        """
        Used to delete corrupted machines
        @param disks: a list of disks
        """
        for machine in machines:
            # We only care about auto-scaled machines that match the regex
            if not re.match(self.machine_name_regex, machine.name):
                continue
            # Delete the machine if:
            # - If a machine's provisioning state is Failed, delete it
            # - If a machine was created by Azure and then Azure couldn't find it, odds are the auto-scaled tags were
            # not appended and thus the machine was not included further in the Cuckoo system
            # - If a machine has been deallocated because it is a spot instance, delete it
            if machine.provisioning_state == "Failed":
                log.warning("Deleting machine '%s' because it failed to provision.", machine.name)
                self._delete_machine(machine.name)
            elif not self._is_auto_scaled(machine.tags):
                log.warning("Deleting machine '%s' because it was not auto-scaled." % machine.name)
                self._delete_machine(machine.name)
            elif self._status(machine.name) == Azure.POWEROFF:
                log.warning("Deleting machine '%s' because it was deallocated." % machine.name)
                self._delete_machine(machine.name)

    def _add_resource_to_delete_set(self, resource_type, name):
        """
        Used to add resources to set for deletion
        @param resource_type: the type of resource to be deleted
        @param name: the name of the resource to be deleted
        """
        global nics_to_delete
        global disks_to_delete
        valid_resource_types_to_delete = [self.NIC_KEY, self.DISK_KEY]
        if resource_type not in valid_resource_types_to_delete:
            raise CuckooMachineError("Resource type %s in _add_resource_to_delete_set is not in "
                                     "%s." % (resource_type, valid_resource_types_to_delete))
        if resource_type == self.NIC_KEY:
            if re.match(self.nic_name_regex, name):
                nics_to_delete.add(name)
        elif resource_type == self.DISK_KEY:
            if re.match(self.disk_name_regex, name):
                disks_to_delete.add(name)


def _azure_api_call(*args, **kwargs):
    """
    This method is used as a common place for all Azure API calls
    @param args: any argument that an Azure API call takes
    @param kwargs: the API call operation, and sometimes tags
    @raise CuckooMachineError: if there is a problem with the Azure call
    @return: dict containing results of API call
    """
    global api_call_counts
    # I figured this was the most concrete way to guarantee that an API method was being passed
    if not kwargs["operation"]:
        raise CuckooMachineError("kwargs in _azure_api_call requires 'operation' parameter.")
    operation = kwargs["operation"]

    # Note that tags is a special keyword parameter in some operations
    tags = kwargs.get("tags", None)

    curframe = inspect.currentframe()
    calframe = inspect.getouterframes(curframe, 2)
    caller_name = calframe[1][3]
    operation_string = str(operation)
    operation_items = operation_string.split(" ")
    method = operation_items[2]
    api_count_key = "%s:%s" % (caller_name, method)
    if api_call_counts.get(api_count_key):
        api_call_counts[api_count_key] += 1
    else:
        api_call_counts[api_count_key] = 1
    log.debug("API call counts: %s", api_call_counts)

    # This is used for logging
    api_call = "%s(%s)" % (operation, args)

    try:
        log.debug("Trying %s", api_call)
        results = operation(*args, tags=tags)
    except Exception as exc:
        log.warning("Failed to %s due to the Azure error '%s': '%s'.",
                    api_call, exc.error.error, exc.message)
        raise CuckooMachineError("%s:%s" % (exc.error.error, exc.message))
    return results


def _get_image_details(label):
    """
    Returns specific values used for a variety of reasons
    @param label: Sometimes the machine name/label, sometimes the snapshot name
    @return: tag string, os_type string, platform string
    """
    platform = "windows"
    if Azure.WINDOWS_10 in label:
        tag = Azure.WINDOWS_10
        os_type = "Windows10x64"
    elif Azure.WINDOWS_7 in label:
        tag = Azure.WINDOWS_7
        os_type = "Windows7x64"
    elif Azure.UBUNTU_1804 in label:
        tag = Azure.UBUNTU_1804
        os_type = "Ubuntu18.04x64"
        platform = "linux"
    else:
        tag = Azure.WINDOWS_7
        os_type = "Windows7x64"
    return tag, os_type, platform


def _resize_machines_being_created(tag, direction):
    """
    Increments or decrements global count indicating value
    of machines being created
    @param tag: String that represents type of machine to create
    @param direction: String that represents direction in which to resize count
    """
    global number_of_ub1804_machines_being_created
    global number_of_win10_machines_being_created
    global number_of_win7_machines_being_created

    operator_lookup = {
        "+": operator.add,
        "-": operator.sub
    }
    operation = operator_lookup.get(direction)

    # Depending on the tag, resize the global count of a certain type
    # of machine being created
    if tag == Azure.WINDOWS_10:
        number_of_win10_machines_being_created = operation(number_of_win10_machines_being_created, 1)
    elif tag == Azure.UBUNTU_1804:
        number_of_ub1804_machines_being_created = operation(number_of_ub1804_machines_being_created, 1)
    else:
        number_of_win7_machines_being_created = operation(number_of_win7_machines_being_created, 1)
