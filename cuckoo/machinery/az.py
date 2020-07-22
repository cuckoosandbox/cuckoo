# Copyright (C) 2015-2020 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.
# in https://github.com/CheckPointSW/Cuckoo-AWS.
# Modified by the Canadian Centre for Cyber Security to support Azure.

import logging
import threading
import sys
from datetime import datetime
import time

from sqlalchemy.exc import SQLAlchemyError

try:
    from azure.common.credentials import ServicePrincipalCredentials
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.compute.models import DiskCreateOption

    from msrestazure.azure_exceptions import CloudError
    HAVE_AZURE = True
except ImportError:
    HAVE_AZURE = False

from cuckoo.common.abstracts import Machinery
from cuckoo.common.config import config
from cuckoo.common.exceptions import CuckooMachineError, CuckooDependencyError

# Only log INFO or higher
logging.getLogger("adal-python").setLevel(logging.INFO)
logging.getLogger("msrest.universal_http").setLevel(logging.INFO)
logging.getLogger("msrest.service_client").setLevel(logging.INFO)
log = logging.getLogger(__name__)


class Azure(Machinery):
    """Virtualization layer for Azure."""

    # VM states.
    PENDING = "pending"
    STOPPING = "stopping"
    RUNNING = "running"
    POWEROFF = "poweroff"
    DELETING = "deleting"
    ABORTED = "failed"
    ERROR = "machete"

    # VM tag that indicates autoscaling.
    AUTOSCALE_CUCKOO = "AUTOSCALE_CUCKOO"

    # Arbitrary value for very large JSON results.
    # Relative to Python environment of machine.
    sys.setrecursionlimit(10000)

    def _initialize(self, module_name):
        """
        Initializing instance parameters.
        @param module_name: module name
        """
        super(Azure, self)._initialize(module_name)

        self.azure_machines = {}
        self.machine_queue = []
        self.dynamic_machines_sequence = 0
        self.dynamic_machines_count = 0
        self.initializing = True

        log.debug(
            "Connecting to Azure for the region '%s'.",
            self.options.az.region_name
        )
        credentials = self._get_credentials()
        self.network_client = NetworkManagementClient(
            credentials,
            self.options.az.subscription_id
        )
        self.compute_client = ComputeManagementClient(
            credentials,
            self.options.az.subscription_id
        )

    def _get_credentials(self):
        """
        Used to create the Azure Credentials object.
        @return: an Azure ServicePrincipalCredentials object
        """
        credentials = ServicePrincipalCredentials(
            client_id=self.options.az.client_id,
            secret=self.options.az.secret,
            tenant=self.options.az.tenant
        )
        return credentials

    def _initialize_check(self):
        """
        Setting up the Azure resource group by doing the following:
        - Cleaning up autoscaled instances from previous Cuckoo runs
        - Cleaning up resources related to those instances
        - Stopping instances that we want to keep
        - Looking for all machines that match the specific machines in az.conf
        and load them into azure_machines dictionary
        - Start or create the required amount of instances as specified
        in az.conf
        @raise CuckooMachineError: if there is a problem with the Azure call
        """
        # Base checks.
        super(Azure, self)._initialize_check()

        if not HAVE_AZURE:
            raise CuckooDependencyError("Unable to import Azure packages")

        self.environment = self.options.az.environment

        try:
            log.debug(
                "Retrieving the subnet '%s'.",
                self.options.az.cuckoo_subnet
            )
            self.subnet_info = self.network_client.subnets.get(
                self.options.az.group,
                self.options.az.vnet,
                self.options.az.cuckoo_subnet
            )
        except CloudError as exc:
            log.debug(
                "Failed to retrieve subnet '%s' due to the Azure error " +
                "'%s': '%s'.",
                self.options.az.cuckoo_subnet,
                exc.error.error,
                exc.message
            )
            raise CuckooMachineError(exc.message)

        try:
            log.debug("Retrieving all virtual machines in resource group.")
            instances = self.compute_client.virtual_machines.list(
                self.options.az.group
            )
            for instance in instances:
                # Cleaning up autoscaled instances from previous Cuckoo runs.
                if self._is_autoscaled(instance) and self.environment in instance.name:
                    self._delete_instance(instance.name)
        except CloudError as exc:
            log.debug(
                "Failed to retrieve all virtual machines due to the " +
                "Azure error '%s': '%s'.",
                exc.error.error, exc.message
            )
            raise CuckooMachineError(exc.message)

        try:
            log.debug(
                "Retrieving the snapshot '%s' to be used to create " +
                "victim disks.",
                self.options.autoscale.guest_snapshot
            )
            snapshot = self.compute_client.snapshots.get(
                self.options.az.group,
                self.options.autoscale.guest_snapshot
            )
            self.snap_id = snapshot.id
        except CloudError as exc:
            log.debug(
                "Failed to retrieve '%s' due to the Azure error '%s': '%s'.",
                self.options.autoscale.guest_snapshot,
                exc.error.error,
                exc.message
            )
            raise CuckooMachineError(exc.message)

        log.info("Deleting leftover network interface cards, managed disks " +
                 "and failed instances.")
        # Cleaning up resources related to those instances.
        self._delete_leftover_resources()

        # Looking for all machines that match the specific machines in az.conf
        # and load them into azure_machines dictionary.
        instance_names = self._list()
        machines = self.machines()
        for machine in machines:
            if machine.label not in instance_names:
                continue
            try:
                log.debug(
                    "Retrieving '%s' instance, setting in azure_machines dict.",
                    machine.label
                )
                self.azure_machines[machine.label] = \
                    self.compute_client.virtual_machines.get(
                        self.options.az.group,
                        machine.label
                    )
            except CloudError as exc:
                log.debug("Failed to retrieve '%s' due to the Azure error " +
                          "'%s': '%s'.",
                          machine.label, exc.error.error, exc.message)
                raise CuckooMachineError(exc.message)

            # Stopping instances that we want to keep.
            if self._status(machine.label) != Azure.POWEROFF:
                self.stop(label=machine.label)

        # Start or create the required amount of instances as specified in
        # az.conf.
        self._start_or_create_machines()

        # The system is now no longer in the initializing phase.
        self.initializing = False

    def _is_autoscaled(self, instance):
        """
        Checks if the instance has a tag that indicates that it was created as
        a result of autoscaling.
        @param instance: instance object
        @return: Boolean indicating if the instance in autoscaled
        """
        if instance.tags and instance.tags.get(self.AUTOSCALE_CUCKOO) == "True":
            return True
        return False

    def _delete_machine_from_db(self, label):
        """
        Implementing machine deletion from Cuckoo's database.
        @param label: the machine label
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

    def _start_or_create_machines(self):
        """
        Start preconfigured machines that are stopped, then allocate new
        machines if the autoscaled option has been selected in the
        configurations.
        Based on the "gap" in az.conf, ensure that there are x machines to be
        created if there are less available machines than the gap.
        """
        # Read configuration file.
        machinery_options = self.options.az
        autoscale_options = self.options.autoscale

        current_available_machines = self.db.count_machines_available()
        running_machines_gap = machinery_options.get("running_machines_gap", 0)
        dynamic_machines_limit = autoscale_options["dynamic_machines_limit"]

        # Start preconfigured machines that are stopped.
        self._start_next_machines(
            num_of_machines_to_start=min(
                current_available_machines,
                running_machines_gap
            )
        )

        #  If there are no available machines left  -> launch a new machine.
        threads = []
        while autoscale_options.autoscale and \
                current_available_machines < running_machines_gap:
            # Sleeping for a couple because Azure takes a while
            time.sleep(2)
            if self.dynamic_machines_count >= dynamic_machines_limit:
                log.debug(
                    "Reached dynamic machines limit - %d machines.",
                    dynamic_machines_limit
                )
                break
            else:
                # Using threads to create machines in parallel.
                self.dynamic_machines_count += 1
                thr = threading.Thread(target=self._allocate_new_machine)
                threads.append(thr)
                thr.start()
                current_available_machines += 1

        # Waiting for all machines to finish being created,
        # depending on the system state.
        if self.initializing:
            for thr in threads:
                thr.join()

    def _start_next_machines(self, num_of_machines_to_start):
        """
        If there are preconfigured machines that are stopped or stopping in
        the database, we want to start them. We want to prepare x machines, so
        that once a task arrives there will be machines ready with the
        operating system launched and the Cuckoo agent listening.
        @param num_of_machines_to_start: how many machines (first in queue)
        will be started
        @raise CuckooMachineError: if there is a problem with the Azure call
        """
        for machine in self.db.get_available_machines():
            if num_of_machines_to_start <= 0:
                break
            if self._status(machine.label) in [Azure.POWEROFF, Azure.STOPPING]:
                try:
                    log.debug("Starting '%s'.", machine.label)
                    self.compute_client.virtual_machines.start(
                        self.options.az.group,
                        machine.label
                    )
                except CloudError as exc:
                    log.debug(
                        "Failed to start '%s' due to the Azure error " +
                        "'%s': '%s'.",
                        machine.label,
                        exc.error.error,
                        exc.message
                    )
                    raise CuckooMachineError(exc.message)

                num_of_machines_to_start -= 1

    def _allocate_new_machine(self):
        """
        Creating new Azure VM, if the autoscale option is selected.
        The process is as follows:
        - Create network interface card for subnet
        - Create instance with network interface card
        - If all goes well, add machine to database
        @return: Signals to thread that method is finished
        """
        # Read configuration file.
        machinery_options = self.options.az
        autoscale_options = self.options.autoscale

        # If configured, use specific network interface,
        # resultserver_ip for this machine, else use the default value.
        interface = autoscale_options.get(
            "interface",
            machinery_options.interface
        )
        resultserver_ip = autoscale_options.get(
            "resultserver_ip",
            config("cuckoo:resultserver:ip")
        )

        if autoscale_options.resultserver_port:
            resultserver_port = autoscale_options.resultserver_port
        else:
            # The ResultServer port might have been dynamically changed,
            # get it from the ResultServer singleton. Also avoid import
            # recursion issues by importing ResultServer here.
            from cuckoo.core.resultserver import ResultServer
            resultserver_port = ResultServer().port

        self.dynamic_machines_sequence += 1
        new_machine_name = "%scuckoo%03d" % (self.environment, self.dynamic_machines_sequence)

        # Avoiding collision on machine name if machine is still deleting.
        instance_names = self._list()
        for instance in instance_names:
            while instance == new_machine_name:
                self.dynamic_machines_sequence = \
                    self.dynamic_machines_sequence + 1
                new_machine_name = "%scuckoo%03d" % (self.environment, self.dynamic_machines_sequence)

        # Create network interface card (NIC).
        new_machine_nic = self._create_nic(
            "nic-01",
            new_machine_name,
            resultserver_ip
        )
        nic_private_ip = new_machine_nic.ip_configurations[0].private_ip_address

        # For some reason Azure cannot create multiple NICs
        # in parallel in rare cases.
        # This clause is to prevent errors being thrown.
        if new_machine_nic is None:
            # Decrementing the count, so that the method caller will try again.
            self.dynamic_machines_count -= 1
            return

        # Create Azure VM, tagged as autoscaled and with the new NIC.
        guest_instance = self._create_instance(
            new_machine_nic,
            tags={"Name": new_machine_name, self.AUTOSCALE_CUCKOO: True}
        )

        # There are occasions where Azure fails to create an instance.
        if guest_instance is None:
            try:
                nic_name = "nic-01-" + new_machine_name
                log.debug("Marking instance NIC '%s' to be deleted.", nic_name)
                self.network_client.network_interfaces.update_tags(
                    self.options.az.group,
                    nic_name,
                    tags={"status": "to_be_deleted"}
                )
            except CloudError as exc:
                log.debug("Failed to mark '%s' due to the Azure error '%s': '%s'.",
                          "nic-01-"+new_machine_name, exc.error.error, exc.message)
                raise CuckooMachineError(exc.message)

            # Decrementing the count, so that the method caller will try again.
            self.dynamic_machines_count -= 1
            return

        log.info(
            "Allocating a new machine '%s' to meet pool size requirements.",
            new_machine_name
        )
        self.machine_queue.append(new_machine_name)
        self.azure_machines[new_machine_name] = guest_instance
        # Sets "new_machine" object in configuration object to
        # avoid raising an exception.
        setattr(self.options, new_machine_name, {})
        # Add machine to DB.
        self.db.add_machine(
            name=new_machine_name,
            label=new_machine_name,
            ip=nic_private_ip,
            platform=autoscale_options.platform,
            options=autoscale_options.options,
            tags=autoscale_options.tags,
            interface=interface,
            snapshot=autoscale_options.guest_snapshot,
            resultserver_ip=resultserver_ip,
            resultserver_port=resultserver_port
        )
        return

    def acquire(self, machine_id=None, platform=None, tags=None):
        """
        Override Machinery method to utilize the auto scale option
        as well as a FIFO queue for machines.
        @param machine_id: the name of the machine to be acquired
        @param platform: the platform of the machine's operating system
        @param tags: any tags that are associated with the machine
        """
        if self.machine_queue:
            # Used to minimize wait times as VMs are starting up and some might
            # not ready to listen yet.
            machine_id = self.machine_queue.pop(0)
        base_class_return_value = super(Azure, self).acquire(
            machine_id,
            platform,
            tags
        )
        self._start_or_create_machines()  # Prepare another machine
        return base_class_return_value

    def release(self, label=None):
        """
        Override abstract machinery method to have the ability to run
        start_or_create_machines()
        after unlocking the last machine.
        @param label: machine label.
        """
        super(Azure, self).release(label)
        self._start_or_create_machines()

    def _status(self, label):
        """
        Gets current status of a VM.
        @param label: virtual machine label.
        @return: VM state string.
        @raise CuckooMachineError: if there is a problem with the Azure call
        """
        try:
            log.debug("Getting the instance_view details of '%s'.", label)
            instance_view = \
                self.compute_client.virtual_machines.instance_view(
                    self.options.az.group,
                    label
                )
        except CloudError as exc:
            log.debug(
                "Failed to retrieve instance view of '%s' due to the Azure " +
                "error '%s': '%s'.",
                label,
                exc.error.error,
                exc.message
            )
            raise CuckooMachineError(exc.message)

        for status in instance_view.statuses:
            # Ideally, we're looking for the PowerState status.
            if "PowerState" in status.code:
                state = status.code
                break
            # If the PowerState status doesn't exist, then the VM is
            # deleting, or has failed.
            elif "ProvisioningState" in status.code:
                state = status.code
            else:
                state = "Unknown"

        if state == "PowerState/running":
            status = Azure.RUNNING
        elif state == "PowerState/stopped":
            status = Azure.POWEROFF
        elif state == "PowerState/starting":
            status = Azure.PENDING
        elif state == "PowerState/stopping":
            status = Azure.STOPPING
        elif state == "PowerState/deallocating":
            status = Azure.STOPPING
        elif state == "PowerState/deallocated":
            status = Azure.POWEROFF
        elif state == "ProvisioningState/deleting":
            status = Azure.DELETING
        elif state == "ProvisioningState/failed/InternalOperationError":
            status = Azure.ABORTED
        else:
            status = Azure.ERROR
        return status

    def start(self, label, task):
        """
        Start a preconfigured virtual machine.
        @param label: virtual machine label.
        @param task: task object.
        @raise CuckooMachineError: if there is a problem with the Azure call
        """
        log.debug("Starting VM '%s'.", label)
        if not self._is_autoscaled(self.azure_machines[label]):
            try:
                log.debug("Starting '%s'.", label)
                self.compute_client.virtual_machines.start(
                    self.options.az.group,
                    label
                )
            except CloudError as exc:
                log.debug(
                    "Failed to start '%s' due to the Azure error '%s': '%s'.",
                    label,
                    exc.error.error,
                    exc.message
                )
                raise CuckooMachineError(exc.message)
            self._wait_status(label, Azure.RUNNING)

    def stop(self, label=None):
        """
        Deallocates & starts the restoration process for a preconfigured
        virtual machine or if the machine is an autoscaled instance,
        then terminate it.
        Then clean up resources.
        @param label: virtual machine label
        @raise CuckooMachineError: if there is a problem with the Azure call
        """
        log.debug("Stopping vm '%s'.", label)
        if not label:
            return

        status = self._status(label)
        if status == Azure.POWEROFF:
            raise CuckooMachineError(
                "Trying to stop an already stopped VM: '%s'." % label
            )

        if self._is_autoscaled(self.azure_machines[label]) and self.environment in label:
            self._delete_instance(label)
        else:
            try:
                log.debug("Deallocating '%s'.", label)
                self.compute_client.virtual_machines.deallocate(
                    self.options.az.group,
                    label
                )
            except CloudError as exc:
                log.debug(
                    "Failed to deallocate '%s' due to the Azure error " +
                    "'%s': '%s'.",
                    label,
                    exc.error.error,
                    exc.message
                )
                raise CuckooMachineError(exc.message)
            self._wait_status(label, Azure.POWEROFF)
            self._restore(label)

        self._delete_leftover_resources()

    def _restore(self, label):
        """
        Restore the instance according to the configured snapshot (az.conf).
        This method consists of the following:
        - Create a new OS disk from a snapshot
        - Detach the current OS disk,
        - Attach the new OS disk
        - Delete the old disk
        @param label: machine label
        @raise CuckooMachineError: if there is a problem with the Azure call
        """
        log.info("Restoring machine: '%s'.", label)
        instance = self.azure_machines[label]
        # We can only perform this hot swap of OS disks if the VM is
        # deallocated fully.
        state = self._status(label)
        if state != Azure.POWEROFF:
            raise CuckooMachineError(
                "Instance '%s' state '%s' is not poweroff." % (label, state))

        # Create a new OS disk from a snapshot.
        new_disk = self._create_disk_from_snapshot(label)

        log.debug("Swapping OS disk on VM '%s' and updating the VM.", label)
        # By setting this parameter to the new disk, and using it to update
        # the VM, we are effectively detaching the old disk and attaching the
        # new disk.
        instance.storage_profile.os_disk = {
            "create_option": instance.storage_profile.os_disk.create_option,
            "managed_disk": {
                "id": new_disk.id
            }
        }
        try:
            log.debug("Updating the OS disk for the VM '%s'.", instance.name)
            self.compute_client.virtual_machines.create_or_update(
                self.options.az.group,
                instance.name,
                parameters=instance
            )
        except CloudError as exc:
            log.debug(
                "Failed to update '%s' due to the Azure error '%s': '%s'.",
                instance.name,
                exc.error.error,
                exc.message
            )
            raise CuckooMachineError(exc.message)

    def _list(self):
        """
        Retrieves all virtual machines in resource group.
        @return: A list of all instance names within resource group
        @raise CuckooMachineError: if there is a problem with the Azure call
        """
        try:
            log.debug("Retrieving all virtual machines in resource group.")
            instances = self.compute_client.virtual_machines.list(
                self.options.az.group
            )
        except CloudError as exc:
            log.debug(
                "Failed to retrieve all virtual machines due to the " +
                "Azure error '%s': '%s'.",
                exc.error.error,
                exc.message
            )
            raise CuckooMachineError(exc.message)

        return [instance.name for instance in instances]

    def _create_nic(self, nic_name, computer_name, dns_server):
        """
        Used to create the Azure network interface card.
        @param nic_name: name of the new nic
        @param computer_name: name of VM that nic is going to be attached to
        @param dns_server: name of server that DNS resolution will take place
        @return: a network interface card object
        @raise CuckooMachineError: if there is a problem with the Azure call
        """

        nic_params = {
            "location": self.options.az.region_name,
            "ip_configurations": [{
                "name": "myIPConfig",
                "subnet": {
                    "id": self.subnet_info.id
                }
            }],
            "dns_settings": {
                "dns_servers": [dns_server]
            }
        }
        nic_name = nic_name + "-" + computer_name
        try:
            log.debug("Creating the NIC '%s'.", nic_name)
            async_nic_creation = \
                self.network_client.network_interfaces.create_or_update(
                    self.options.az.group,
                    nic_name,
                    nic_params
                )
            async_nic_creation.wait()
            nic = async_nic_creation.result()
            return nic
        except CloudError as exc:
            log.debug(
                "NIC '%s' was not created due to the Azure error " +
                "'%s': '%s'.",
                nic_name,
                exc.error.error,
                exc.message
            )
            return None

    def _create_instance(self, nic, tags):
        """
        Create a new instance consists of the following process:
        - Create an OS disk from a snapshot
        - Setup parameters to be used in client API calls
        - Create instance using these parameters
        @param nic: network interface card to be attached to guest VM
        @param tags: tags to attach to instance
        @return: the new instance
        """
        # Read configuration file.
        autoscale_options = self.options.autoscale
        computer_name = tags["Name"]

        new_disk = self._create_disk_from_snapshot(computer_name)
        os_disk = {
            "create_option": "Attach",
            "managed_disk": {
                "id": new_disk.id,
                "storage_account_type": autoscale_options.storage_account_type
            },
            "osType": autoscale_options.platform
        }

        vm_parameters = {
            "location": self.options.az.region_name,
            "tags": tags,
            "properties": {
                "hardwareProfile": {
                    "vmSize": autoscale_options.instance_type
                },
                "storageProfile": {
                    "osDisk": os_disk
                }
            },
            "networkProfile": {
                "networkInterfaces": [{
                    "id": nic.id,
                    "properties": {"primary": True}
                }]
            }
        }
        try:
            log.debug("Creating the instance '%s'.", computer_name)
            async_vm_creation = \
                self.compute_client.virtual_machines.create_or_update(
                    self.options.az.group,
                    computer_name,
                    vm_parameters
                )
        except CloudError as exc:
            log.debug(
                "Failed to create '%s' due to the Azure error '%s': '%s'.",
                 computer_name,
                exc.error.error,
                exc.message
            )
            return None

        # Wait for asynchronous call to finish, then return instance.
        new_instance = async_vm_creation.result()
        log.debug("Created '%s'\n%s.", new_instance.id, repr(new_instance))
        return new_instance

    def _create_disk_from_snapshot(self, new_computer_name):
        """
        Uses a snapshot in the resource group to create a managed OS disk.
        :param snapshot_name: String indicating the name of the snapshot
        :param new_computer_name: String indicating the name of the VM to be created
        :return: an Azure Managed OS Disk object
        @raise CuckooMachineError: if there is a problem with the Azure call
        """
        log.debug("Creating disk which is a copy of a snapshot.")

        new_disk_name = "osdisk" + new_computer_name
        try:
            log.debug(
                "Creating a managed disk '%s' using the snapshot.",
                new_disk_name
            )
            async_disk_creation = self.compute_client.disks.create_or_update(
                self.options.az.group,
                new_disk_name,
                {
                    "location": self.options.az.region_name,
                    "creation_data": {
                        "create_option": DiskCreateOption.copy,
                        "source_uri": self.snap_id
                    }
                }
            )
            async_disk_creation.wait()
            return async_disk_creation.result()
        except CloudError as exc:
            log.debug(
                "Failed to create managed disk '%s' due to the Azure error " +
                "'%s': '%s'.",
                new_disk_name,
                exc.error.error,
                exc.message
            )
            raise CuckooMachineError(exc.message)

    def _delete_instance(self, instance_name):
        """
        Deletes an instance by marking the instance's NIC for deletion,
        and then deleting the VM
        :param instance_name: String indicating the name of the VM to be deleted
        @raise CuckooMachineError: if there is a problem with the Azure call
        """
        try:
            nic_name = "nic-01-" + instance_name
            log.debug("Marking instance NIC '%s' to be deleted.", nic_name)
            self.network_client.network_interfaces.update_tags(
                self.options.az.group,
                nic_name,
                tags={"status": "to_be_deleted"}
            )
        except CloudError as exc:
            log.debug("Failed to mark '%s' due to the Azure error '%s': '%s'.",
                      "nic-01-"+instance_name, exc.error.error, exc.message)
            raise CuckooMachineError(exc.message)

        try:
            log.info("Terminating autoscaling instance '%s'.", instance_name)
            self.compute_client.virtual_machines.delete(
                self.options.az.group,
                instance_name
            )

            # If the state of the system is past being initialized,
            # then delete the VM entry from the DB.
            if not self.initializing:
                self._delete_machine_from_db(instance_name)
                self.dynamic_machines_count -= 1
        except CloudError as exc:
            log.debug(
                "Failed to delete instance '%s' due to the Azure error " +
                "'%s': '%s'.",
                instance_name,
                exc.error.error,
                exc.message
            )
            raise CuckooMachineError(exc.message)

    def _delete_leftover_resources(self):
        """
        Used to clean up the resources that aren't cleaned up when a VM is
        deleted.
        @raise CuckooMachineError: if there is a problem with the Azure call
        """
        try:
            log.debug("Listing all network interface cards in resource group.")
            nics = self.network_client.network_interfaces.list(
                self.options.az.group
            )
        except CloudError as exc:
            log.debug(
                "Failed to list network interface cards due to the Azure " +
                "error '%s': '%s'.",
                exc.error.error,
                exc.message
            )
            raise CuckooMachineError(exc.message)

        threads = []
        if nics:
            # Iterate over all network interface cards to check if any are not
            # associated to a VM.
            for nic in nics:
                nic_is_detached = nic.virtual_machine is None and \
                                  nic.primary is None and \
                                  nic.provisioning_state == "Succeeded"
                nic_is_to_be_deleted = \
                    nic.tags and nic.tags.get("status", "") == "to_be_deleted"
                if nic_is_detached and nic_is_to_be_deleted:
                    try:
                        log.debug(
                            "Deleting leftover network interface card '%s'.",
                            nic.name
                        )
                        async_delete_nic = \
                            self.network_client.network_interfaces.delete(
                                self.options.az.group,
                                nic.name
                            )
                    except CloudError as exc:
                        print(nic)  # For troubleshooting.
                        log.error(
                            "Failed to delete '%s' due to the Azure error " +
                            "'%s': '%s'.",
                            nic.name,
                            exc.error.error,
                            exc.message
                        )
                        continue

                    if self.initializing:
                        thr = threading.Thread(target=async_delete_nic.wait)
                        threads.append(thr)
                        thr.start()

        if self.initializing:
            for thr in threads:
                # Need to wait for each network interface card to delete
                # during initialization.
                thr.join()

        try:
            log.debug("Listing all managed disks in resource group.")
            disks = self.compute_client.disks.list_by_resource_group(
                self.options.az.group
            )
        except CloudError as exc:
            log.debug(
                "Failed to list managed disks due to the Azure error " +
                "'%s': '%s'.",
                exc.error.error,
                exc.message
            )
            raise CuckooMachineError(exc.message)

        # Iterate over all OS disks to check if any are not associated to a VM.
        for disk in disks:
            timestamp = time.mktime(disk.time_created.timetuple())
            time_delta = datetime.now() - datetime.fromtimestamp(timestamp)
            # If the disk is unattached and has been around for three minutes,
            # then the disk can be deleted.
            if disk.disk_state == "Unattached" and \
                    time_delta.total_seconds() > 180:
                try:
                    log.debug("Deleting leftover managed disk '%s'.", disk.name)
                    self.compute_client.disks.delete(
                        self.options.az.group,
                        disk.name
                    )
                except CloudError as exc:
                    print(disk)  # For troubleshooting.
                    log.error(
                        "Failed to delete '%s' managed disks due to the " +
                        "Azure error '%s': '%s'.",
                        disk.name,
                        exc.error.error,
                        exc.message
                    )
                    continue

        # Iterate over all instances to check if they're deployment
        # state is Failed.
        try:
            log.debug("Retrieving all virtual machines in resource group.")
            instances = self.compute_client.virtual_machines.list(
                self.options.az.group
            )
        except CloudError as exc:
            log.debug("Failed to list virtual machines due to the Azure " +
                      "error '%s': '%s'.",
                      exc.error.error, exc.message)
            raise CuckooMachineError(exc.message)
        for instance in instances:
            if instance.provisioning_state == "Failed" and self.environment in instance.name:
                log.debug(
                    "Deleting instance that failed to deploy '%s'.",
                    instance.name
                )
                self._delete_instance(instance.name)