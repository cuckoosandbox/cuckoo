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
import socket

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

vmlistcountinlist = 0
vmlistcountininitializecheck = 0
vmlistcountindeleteleftoverresources = 0
niclistcount = 0
disklistcount = 0
vmcreatecount = 0
niccreatecount = 0
diskcreatecount = 0
vnetcheckipcount = 0
vmdeletecount = 0
nicdeletecount = 0
diskdeletecount = 0
nicupdatetagcount = 0
subnetgetcount = 0
snapshotgetcount = 0
vminstanceviewcount = 0



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
        Overloading abstracts.py:_initialize()
        Initializing instance parameters.
        @param module_name: module name
        """
        if not HAVE_AZURE:
            raise CuckooDependencyError("Unable to import Azure packages")

        self.azure_machines = {}
        self.machine_queue = []
        self.dynamic_machines_count = 0
        self.initializing = True
        self.dynamic_machines_limit = self.options.az.dynamic_machines_limit
        self.running_machines_gap = float(self.options.az.running_machines_gap/100.0)
        self._thr_refresh_clients()

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

    def _thr_refresh_clients(self):
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
        # Refresh clients every half hour
        threading.Timer(1800, self._thr_refresh_clients).start()

    def _initialize_check(self):
        """
        Overloading abstracts.py:_initialize_check()
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
        global subnetgetcount, vmlistcountininitializecheck, snapshotgetcount
        self.environment = self.options.az.environment
        subnetgetcount += 1
        self.subnet_info = _azure_api_call(
            self.options.az.group,
            self.options.az.vnet,
            self.options.az.cuckoo_subnet,
            operation=self.network_client.subnets.get,
        )

        vmlistcountininitializecheck += 1
        instances = _azure_api_call(
            self.options.az.group,
            operation=self.compute_client.virtual_machines.list
        )

        for instance in instances:
            # Cleaning up autoscaled instances from previous Cuckoo runs.
            if self._is_autoscaled(instance) and self.environment in instance.name:
                self._delete_instance(instance.name)

        self.snap_ids = []
        for snapshot in self.options.az.guest_snapshot:
            snapshotgetcount += 1
            snapshot_resource = _azure_api_call(
                self.options.az.group,
                snapshot,
                operation=self.compute_client.snapshots.get
            )
            self.snap_ids.append(snapshot_resource.id)

        log.info("Deleting leftover network interface cards, managed disks " +
                 "and failed instances.")
        # Cleaning up resources related to those instances.
        self._delete_leftover_resources()

        create_vms_per_snap_threads = []
        for snap_id in self.snap_ids:
            log.debug("Starting or creating machines for snapshot: %s" % snap_id)
            thr = threading.Thread(target=self._create_machines, args=(snap_id,))
            create_vms_per_snap_threads.append(thr)
            thr.start()

        for thr in create_vms_per_snap_threads:
            thr.join()
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

    def _create_machines(self, snap_id):
        """
        Start preconfigured machines that are stopped, then allocate new
        machines if the autoscaled option has been selected in the
        configurations.
        Based on the "gap" in az.conf, ensure that there are x machines to be
        created if there are less available machines than the gap.
        """
        log.debug("vmlistcountinlist %d; vmlistcountindeleteleftoverresources %d; vmlistcountininitializecheck %d; niclistcount %d; disklistcount %d; vmcreatecount %d;"
                  " niccreatecount %d; diskcreatecount %d; vnetcheckipcount %d; vmdeletecount %d;"
                  " nicdeletecount %d; diskdeletecount %d; nicupdatetagcount %d; subnetgetcount %d; "
                  "snapshotgetcount %d; vminstanceviewcount %d;",
            vmlistcountinlist, vmlistcountindeleteleftoverresources, vmlistcountininitializecheck, niclistcount, disklistcount, vmcreatecount, niccreatecount,
            diskcreatecount, vnetcheckipcount, vmdeletecount, nicdeletecount, diskdeletecount,
            nicupdatetagcount, subnetgetcount, snapshotgetcount, vminstanceviewcount)
        global number_of_win7_machines_being_created
        global number_of_win10_machines_being_created
        global number_of_ub1804_machines_being_created

        # We are getting a list of all available (unlocked) machines
        available_machines = self.db.get_available_machines()

        # Assigning the appropriate tag based on snapshot ID
        tag, os_type, platform = _get_image_details(snap_id)
        # The number of relevant available machines are those from the list that have the correct tag in their name
        relevant_available_machines = len([machine for machine in available_machines if tag in machine.label])

        #  If there are no available machines left  -> launch a new machine.
        threads = []
        # The task queue will be relative to the virtual machine os type that is targeted
        tasks = self.db.list_tasks(status="pending")
        relevant_task_queue = 0
        for task in tasks:
            for t in task.tags:
                if t.name == tag:
                    relevant_task_queue += 1

        if relevant_task_queue == 0:
            relevant_task_queue = self.options.az.initial_pool_size  # We want a minimum of X machines * running_machines_gap% running at rest for each snapshot id
        number_of_relevant_available_machines_required = int(round(relevant_task_queue*self.running_machines_gap)) - relevant_available_machines

        if tag == "win10":
            number_of_relevant_machines_being_created = number_of_win10_machines_being_created
        elif tag == "ub1804":
            number_of_relevant_machines_being_created = number_of_ub1804_machines_being_created
        else:
            number_of_relevant_machines_being_created = number_of_win7_machines_being_created

        if number_of_relevant_machines_being_created >= number_of_relevant_available_machines_required:
            return
        number_of_machines_to_create = number_of_relevant_available_machines_required - number_of_relevant_machines_being_created
        log.debug("Machines being created: %d; Machines to create: %d; Need %d available machines;", number_of_relevant_machines_being_created, number_of_machines_to_create, number_of_relevant_available_machines_required)
        for vm_to_be_created in range(number_of_machines_to_create):
            if len(self.machines()) >= self.dynamic_machines_limit:
                log.debug(
                    "Reached dynamic machines limit - %d machines.",
                    self.dynamic_machines_limit
                )
                break
            else:
                # Using threads to create machines in parallel.
                thr = threading.Thread(target=self._thr_allocate_new_machine, args=(tag, snap_id,))
                threads.append(thr)
                thr.start()

        # Waiting for all machines to finish being created,
        # depending on the system state.
        if self.initializing:
            for thr in threads:
                thr.join()

    def _thr_allocate_new_machine(self, tag, snap_id):
        """
        Creating new Azure VM, if the autoscale option is selected.
        The process is as follows:
        - Create network interface card for subnet
        - Create instance with network interface card
        - If all goes well, add machine to database
        @return: Signals to thread that method is finished
        """
        global vnetcheckipcount, nicupdatetagcount
        # Read configuration file.
        machinery_options = self.options.az

        global number_of_win7_machines_being_created
        global number_of_ub1804_machines_being_created
        global number_of_win10_machines_being_created
        global dynamic_machines_sequence

        if tag == "win10":
            number_of_win10_machines_being_created += 1
        elif tag == "ub1804":
            number_of_ub1804_machines_being_created += 1
        else:
            number_of_win7_machines_being_created += 1

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

        dynamic_machines_sequence += 1

        # Adding the appropriate tag if multiple snapshots
        tag, os_type, platform = _get_image_details(snap_id)

        new_machine_name = "cuckoo-%s-%03d-%s" % (self.environment, dynamic_machines_sequence, tag)

        # dict for thread results
        results = {"nic": None, "disk": None}

        # Create two child threads, one for creating the NIC and one for creating the disk
        nic_thr = threading.Thread(target=self._thr_create_nic, args=("nic-01", new_machine_name, resultserver_ip, results,))

        # Start 'em up!
        nic_thr.start()

        # Wait for 'em to finish
        nic_thr.join()
        new_nic = results["nic"]
        if new_nic == "SubnetIsFull":
            # Bail!
            return

        if not new_nic:
            # Bail!
            log.debug("Failed to create NIC.")
            return

        disk_thr = threading.Thread(target=self._thr_create_disk_from_snapshot, args=(new_machine_name, results, snap_id,))
        disk_thr.start()
        disk_thr.join()

        new_disk = results["disk"]

        if not new_disk:
            log.debug("Failed to create disk.")
            raise CuckooMachineError("Problems!")

        vm_creation_time = time.time()
        # Create Azure VM, tagged as autoscaled and with the new NIC.
        guest_instance = self._create_instance(
            new_nic,
            tags={"Name": new_machine_name, self.AUTOSCALE_CUCKOO: True},
            platform=platform,
            disk_id=new_disk.id
        )

        # There are occasions where Azure fails to create an instance.
        if guest_instance is None:
            nic_name = "nic-01-" + new_machine_name
            log.debug("Marking instance NIC '%s' to be deleted.", nic_name)
            nicupdatetagcount += 1
            _azure_api_call(
                self.options.az.group,
                nic_name,
                tags={"status": "to_be_deleted"},
                operation=self.network_client.network_interfaces.update_tags
            )
            return

        self.machine_queue.append(new_machine_name)
        self.azure_machines[new_machine_name] = guest_instance
        # Sets "new_machine" object in configuration object to
        # avoid raising an exception.
        setattr(self.options, new_machine_name, {})
        tags = os_type + ", " + machinery_options.tags
        ip = new_nic.ip_configurations[0].private_ip_address
        # Add machine to DB.
        self.db.add_machine(
            name=new_machine_name,
            label=new_machine_name,
            ip=ip,
            platform=platform,
            options=machinery_options.options,
            tags=tags,
            interface=interface,
            snapshot=machinery_options.guest_snapshot,
            resultserver_ip=resultserver_ip,
            resultserver_port=resultserver_port
        )
        # Setting the status of the machine, it's been created, but it's not ready to be set to available yet
        self.db.set_machine_status(new_machine_name, "initializing")
        machine = self.db.view_machine(new_machine_name)
        # Now we're going to wait for the machine to be have the agent all set up
        if self.initializing:
            """
                Wait until the Virtual Machine is available for usage. 
                Majority of this code is copied from cuckoo/core/guest.py:GuestManager.wait_available()
            """
            end = time.time() + config("cuckoo:timeouts:vm_state")
            while machine.status == "initializing":
                try:
                    socket.create_connection((ip, CUCKOO_GUEST_PORT), 1).close()
                    self.db.set_machine_status(new_machine_name, "available")
                    break
                except socket.timeout:
                    log.debug("%s: Initializing...", new_machine_name)
                except socket.error:
                    log.debug("%s: Initializing...", new_machine_name)
                time.sleep(10)

                if time.time() > end:
                    raise CuckooGuestCriticalTimeout(
                        "Machine %s: the guest initialization hit the critical "
                        "timeout, analysis aborted." % new_machine_name
                    )
            log.debug("Machine %s was created and available in %9.3fs", new_machine_name, time.time() - vm_creation_time)

        if tag == "win10":
            number_of_win10_machines_being_created -= 1
        elif tag == "ub1804":
            number_of_ub1804_machines_being_created -= 1
        else:
            number_of_win7_machines_being_created -= 1
        return

    def acquire(self, machine_id=None, platform=None, tags="win7"):
        """
        Override Machinery method to utilize the auto scale option
        as well as a FIFO queue for machines.
        @param machine_id: the name of the machine to be acquired
        @param platform: the platform of the machine's operating system
        @param tags: any tags that are associated with the machine
        """
        requested_type = None
        if type(tags) == list and len(tags) > 0:
            requested_type = tags[0]
        elif type(tags) == list and len(tags) == 0:
            requested_type = "unknown_guest_image"
        if self.machine_queue:
            # Used to minimize wait times as VMs are starting up and some might
            # not be ready to listen yet.
            first_index_of_correct_machine = next((x for x, val in enumerate(self.machine_queue) if requested_type in val), None)
            if not first_index_of_correct_machine:
                machine_id = self.machine_queue.pop(0)
            else:
                machine_id = self.machine_queue.pop(first_index_of_correct_machine)
        # Note that tags are ignored in future because machine_id is used
        base_class_return_value = super(Azure, self).acquire(
            machine_id=machine_id,
            platform=platform,
            tags=tags
        )
        tag, os_type, platform = _get_image_details(base_class_return_value.label)
        self._delete_leftover_resources()  # Delete leftover NICs and disks
        if tag != requested_type:
            # If we acquired a vm due to it being the oldest but of the wrong requested type,
            # we want to replace the vm in the pool while also preparing the pool for
            # the requested type
            used_snap_id = next(snap_id for snap_id in self.snap_ids if tag in snap_id)
            self._create_machines(used_snap_id)

        requested_snap_id = next(snap_id for snap_id in self.snap_ids if requested_type in snap_id)  # This has to return something
        self._create_machines(requested_snap_id)  # Prepare another machine
        return base_class_return_value

    def _status(self, label):
        """
        Gets current status of a VM.
        @param label: virtual machine label.
        @return: VM state string.
        @raise CuckooMachineError: if there is a problem with the Azure call
        """
        instance_view = _azure_api_call(
            self.options.az.group,
            label,
            operation=self.compute_client.virtual_machines.instance_view
        )

        state = None
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

    # We have to "implement" this
    def start(self, label, task):
        pass

    def stop(self, label=None):
        """
        If the machine is an autoscaled instance,
        then terminate it.
        Then clean up resources.
        @param label: virtual machine label
        @raise CuckooMachineError: if there is a problem with the Azure call
        """
        log.debug("Deleting the machine '%s'.", label)
        if not label:
            return

        if self._is_autoscaled(self.azure_machines[label]) and self.environment in label:
            self._delete_instance(label)

    def _list(self):
        """
        Retrieves all virtual machines in resource group.
        @return: A list of all instance names within resource group
        @raise CuckooMachineError: if there is a problem with the Azure call
        """
        instances = _azure_api_call(
            self.options.az.group,
            operation=self.compute_client.virtual_machines.list
        )

        return [instance.name for instance in instances]

    def _thr_create_nic(self, nic_name, computer_name, dns_server, results):
        """
        Used to create the Azure network interface card.
        @param nic_name: name of the new nic
        @param computer_name: name of VM that nic is going to be attached to
        @param dns_server: name of server that DNS resolution will take place
        @return: a network interface card object
        @raise CuckooMachineError: if there is a problem with the Azure call
        """
        global niccreatecount
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
            niccreatecount += 1
            async_nic_creation = _azure_api_call(
                self.options.az.group,
                nic_name,
                nic_params,
                operation=self.network_client.network_interfaces.create_or_update
            )
        except CuckooMachineError as exc:
            if "SubnetIsFull" in exc:
                results["nic"] = "SubnetIsFull"
                return
            else:
                raise
        async_nic_creation.wait()
        nic = async_nic_creation.result()
        results["nic"] = nic

    def _create_instance(self, nic, tags, platform, disk_id):
        """
        Create a new instance consists of the following process:
        - Create an OS disk from a snapshot
        - Setup parameters to be used in client API calls
        - Create instance using these parameters
        @param nic: network interface card to be attached to guest VM
        @param tags: tags to attach to instance
        @param platform: general platform type
        @return: the new instance
        """
        global vmcreatecount
        # Read configuration file.
        machinery_options = self.options.az
        computer_name = tags["Name"]

        os_disk = {
            "create_option": "Attach",
            "managed_disk": {
                "id": disk_id,
                "storage_account_type": machinery_options.storage_account_type
            },
            "osType": platform
        }

        vm_parameters = {
            "location": self.options.az.region_name,
            "tags": tags,
            "properties": {
                "hardwareProfile": {
                    "vmSize": machinery_options.instance_type
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
        vmcreatecount += 1
        async_vm_creation = _azure_api_call(
            self.options.az.group,
            computer_name,
            vm_parameters,
            operation=self.compute_client.virtual_machines.create_or_update
        )

        # Wait for asynchronous call to finish, then return instance.
        new_instance = async_vm_creation.result()
        return new_instance

    def _thr_create_disk_from_snapshot(self, new_computer_name, results, snap_id):
        """
        Uses a snapshot in the resource group to create a managed OS disk.
        :param snapshot_name: String indicating the name of the snapshot
        :param new_computer_name: String indicating the name of the VM to be created
        :return: an Azure Managed OS Disk object
        @raise CuckooMachineError: if there is a problem with the Azure call
        """
        global diskcreatecount
        new_disk_name = "osdisk" + new_computer_name
        disk_setup = {
            "location": self.options.az.region_name,
            "creation_data": {
                "create_option": DiskCreateOption.copy,
                "source_uri": snap_id
            }
        }
        diskcreatecount += 1
        async_disk_creation = _azure_api_call(
            self.options.az.group,
            new_disk_name,
            disk_setup,
            operation=self.compute_client.disks.create_or_update
        )
        async_disk_creation.wait()
        disk = async_disk_creation.result()
        results["disk"] = disk

    def _delete_instance(self, instance_name):
        """
        Deletes an instance by marking the instance's NIC for deletion,
        and then deleting the VM
        :param instance_name: String indicating the name of the VM to be deleted
        @raise CuckooMachineError: if there is a problem with the Azure call
        """
        global nicupdatetagcount, vmdeletecount
        nic_name = "nic-01-" + instance_name

        nicupdatetagcount += 1
        _azure_api_call(
            self.options.az.group,
            nic_name,
            tags={"status": "to_be_deleted"},
            operation=self.network_client.network_interfaces.update_tags,
        )

        vmdeletecount += 1
        _azure_api_call(
            self.options.az.group,
            instance_name,
            operation=self.compute_client.virtual_machines.delete
        )

        # If the state of the system is past being initialized,
        # then delete the VM entry from the DB. Otherwise, it wouldn't be in the DB.
        if not self.initializing:
            self._delete_machine_from_db(instance_name)

    def _delete_leftover_resources(self):
        """
        Used to clean up the resources that aren't cleaned up when a VM is
        deleted.
        @raise CuckooMachineError: if there is a problem with the Azure call
        """
        global niclistcount, disklistcount, vmlistcountindeleteleftoverresources
        niclistcount += 1
        nics = _azure_api_call(
            self.options.az.group,
            operation=self.network_client.network_interfaces.list
        )

        disklistcount += 1
        disks = _azure_api_call(
            self.options.az.group,
            operation=self.compute_client.disks.list_by_resource_group
        )

        # Iterate over all instances to check if their deployment
        # state is Failed.
        vmlistcountindeleteleftoverresources += 1
        instances = _azure_api_call(
            self.options.az.group,
            operation=self.compute_client.virtual_machines.list
        )

        # Create three child threads, one for deleting NICs, one for deleting disks,
        # and one for deleting instances
        nics_thr = threading.Thread(target=self._thr_delete_nics, args=(nics,))
        disks_thr = threading.Thread(target=self._thr_delete_disks, args=(disks,))
        instances_thr = threading.Thread(target=self._thr_delete_instances, args=(instances,))

        # Start 'em up!
        nics_thr.start()
        disks_thr.start()
        instances_thr.start()

    def _thr_delete_nics(self, nics):
        global nicdeletecount
        threads = []
        # Iterate over all network interface cards to check if any are not
        # associated to a VM.
        for nic in nics:
            nic_is_detached = nic.virtual_machine is None and \
                              nic.primary is None and \
                              nic.provisioning_state == "Succeeded"
            nic_is_to_be_deleted = \
                nic.tags and nic.tags.get("status", "") == "to_be_deleted"
            if nic_is_detached and nic_is_to_be_deleted:
                nicdeletecount += 1
                async_delete_nic = _azure_api_call(
                    self.options.az.group,
                    nic.name,
                    operation=self.network_client.network_interfaces.delete
                )
                # only wait if we are initializing
                if self.initializing:
                    thr = threading.Thread(target=async_delete_nic.wait)
                    threads.append(thr)
                    thr.start()

        if self.initializing:
            for thr in threads:
                # Need to wait for each network interface card to delete
                # during initialization.
                thr.join()

    def _thr_delete_disks(self, disks):
        global diskdeletecount
        # Iterate over all OS disks to check if any are not associated to a VM.
        for disk in disks:
            timestamp = time.mktime(disk.time_created.timetuple())
            time_delta = datetime.now() - datetime.fromtimestamp(timestamp)
            # If the disk is unattached and has been around for three minutes,
            # then the disk can be deleted.
            if disk.disk_state == "Unattached" and \
                    time_delta.total_seconds() > 180:
                diskdeletecount += 1
                _azure_api_call(
                    self.options.az.group,
                    disk.name,
                    operation=self.compute_client.disks.delete
                )

    def _thr_delete_instances(self, instances):
        for instance in instances:
            if instance.provisioning_state == "Failed" and self.environment in instance.name:
                log.debug(
                    "Deleting instance that failed to deploy '%s'.",
                    instance.name
                )
                self._delete_instance(instance.name)


def _azure_api_call(*args, **kwargs):
    if not kwargs["operation"]:
        raise CuckooMachineError("kwargs in _azure_api_call requires 'operation' parameter.")
    # Note that tags is a special keyword parameter in some operations
    tags = kwargs.get("tags", None)
    operation = kwargs["operation"]
    api_call = "%s(%s)" % (operation, args)
    try:
        log.debug("Trying %s", api_call)
        results = operation(*args, tags=tags)
    except CloudError as exc:
        log.debug("Failed to %s due to the Azure error '%s': '%s'.",
                  api_call, exc.error.error, exc.message)
        raise CuckooMachineError("%s:%s" % (exc.error.error, exc.message))
    return results


def _get_image_details(label):
    platform = "windows"
    if "win10" in label:
        tag = "win10"
        os_type = "Windows10x64"
    elif "win7" in label:
        tag = "win7"
        os_type = "Windows7x64"
    elif "ub1804" in label:
        tag = "ub1804"
        os_type = "Ubuntu18.04x64"
    else:
        tag = "win7"
        os_type = "Windows7x64"
    return tag, os_type, platform
