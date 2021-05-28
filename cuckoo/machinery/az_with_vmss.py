# Copyright (C) 2015-2020 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# Originally contributed by Check Point Software Technologies, Ltd.
# in https://github.com/CheckPointSW/Cuckoo-AWS.
# Modified by the Canadian Centre for Cyber Security to support Azure.

import logging
import threading
import time
import socket

try:
    # Azure-specific imports
    from azure.common.credentials import ServicePrincipalCredentials
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.compute import models
    from msrestazure.polling.arm_polling import ARMPolling
    from msrest.polling import LROPoller
    HAVE_AZURE = True
except ImportError:
    HAVE_AZURE = False

# Cuckoo-specific imports
from cuckoo.common.abstracts import Machinery
from cuckoo.common.config import config
from cuckoo.common.exceptions import CuckooMachineError, CuckooDependencyError, CuckooGuestCriticalTimeout, \
    CuckooMissingMachineError, CuckooConfigurationError
from cuckoo.common.constants import CUCKOO_GUEST_PORT
from cuckoo.core.database import TASK_PENDING, Machine

# SQLAlchemy-specific imports
from sqlalchemy.exc import SQLAlchemyError

# Only log INFO or higher from imported python packages
logging.getLogger("adal-python").setLevel(logging.INFO)
logging.getLogger("msrest.universal_http").setLevel(logging.INFO)
logging.getLogger("msrest.service_client").setLevel(logging.INFO)
log = logging.getLogger(__name__)

# Timeout used for calls that shouldn't take longer than 5 minutes but somehow do
AZURE_TIMEOUT = 300

# Setting the timeout for the ARM Poller to 2 second
ARM_POLLER = ARMPolling(2)

# Global variable which will maintain details about each machine pool
machine_pools = {}

# Global variable which will maintain state for platform scaling
is_platform_scaling = {}


class Azure(Machinery):

    # Resource tag that indicates auto-scaling.
    AUTO_SCALE_CUCKOO_KEY = "AUTO_SCALE_CUCKOO"
    AUTO_SCALE_CUCKOO_VALUE = "True"
    AUTO_SCALE_CUCKOO_TAG = {AUTO_SCALE_CUCKOO_KEY: AUTO_SCALE_CUCKOO_VALUE}

    # Operating System Tag Prefixes
    WINDOWS_TAG_PREFIX = "win"
    LINUX_TAG_PREFIX = "ub"
    VALID_TAG_PREFIXES = [WINDOWS_TAG_PREFIX, LINUX_TAG_PREFIX]

    VMSS_NAME_FORMAT = "vmss-%s-%s"

    # Platform names
    WINDOWS_PLATFORM = "windows"
    LINUX_PLATFORM = "linux"

    def _initialize_check(self):
        """
        Overloading abstracts.py:_initialize_check()
        Running checks against Azure that the configuration is correct.
        @param module_name: module name, currently not used be required
        @raise CuckooDependencyError: if there is a problem with the dependencies call
        """
        if not HAVE_AZURE:
            raise CuckooDependencyError("Unable to import Azure packages")

        # Set the flag that indicates that the system is initializing
        self.initializing = True

        # If the lengths are different, that means there isn't a 1:1 mapping of supported OS tags
        # and gallery images, when there should be.
        if len(self.options.az_with_vmss.supported_os_tags) != len(self.options.az_with_vmss.gallery_image_names):
            raise CuckooConfigurationError(
                "The lengths of self.options.az_with_vmss.supported_os_tags (%s) and "
                "self.options.az_with_vmss.gallery_image_names (%s) are not equal." % (
                    self.options.az_with_vmss.supported_os_tags, self.options.az_with_vmss.gallery_image_names)
            )

        valid_vmss_names = [Azure.VMSS_NAME_FORMAT % (self.options.az_with_vmss.environment, tag)
                            for tag in self.options.az_with_vmss.supported_os_tags]
        # We will be using this as a source of truth for the VMSS configs
        self.required_vmsss = {vmss_name: {"exists": False, "image": None, "os": None, "tag": None}
                               for vmss_name in valid_vmss_names}

        # Starting the thread that sets API clients periodically
        self._thr_refresh_clients()

        # Starting the thread that scales the machine pools periodically
        self._thr_machine_pool_monitor()

        # Initialize the VMSSs that we will be using and not using
        self._set_vmss_stage()

        # Set the flag that indicates that the system is not initializing
        self.initializing = False

    def _get_credentials(self):
        """
        Used to instantiate the Azure ServicePrincipalCredentials object.
        @return: an Azure ServicePrincipalCredentials object
        """

        # Instantiates the ServicePrincipalCredentials object using
        # Azure client ID, secret and Azure tenant ID
        credentials = ServicePrincipalCredentials(
            client_id=self.options.az_with_vmss.client_id,
            secret=self.options.az_with_vmss.secret,
            tenant=self.options.az_with_vmss.tenant
        )
        return credentials

    def _thr_refresh_clients(self):
        """
        A thread on a 30 minute timer that refreshes the network
        and compute clients using an updated ServicePrincipalCredentials
        object.
        """
        log.debug("Connecting to Azure for the region '%s'.", self.options.az_with_vmss.region_name)

        # Getting an updated ServicePrincipalCredentials
        credentials = self._get_credentials()

        # Instantiates an Azure NetworkManagementClient using
        # ServicePrincipalCredentials and subscription ID
        self.network_client = NetworkManagementClient(
            credentials,
            self.options.az_with_vmss.subscription_id
        )

        # Instantiates an Azure ComputeManagementClient using
        # ServicePrincipalCredentials and subscription ID
        self.compute_client = ComputeManagementClient(
            credentials,
            self.options.az_with_vmss.subscription_id
        )

        # Refresh clients every half hour
        threading.Timer(1800, self._thr_refresh_clients).start()

    def _thr_machine_pool_monitor(self):
        """
        A thread on a 5 minute timer that scales the machine pools to
        appropriate levels.
        """
        # Only do it post-initialization
        if self.initializing:
            pass
        else:
            log.debug("Monitoring the machine pools...")
            for vmss, vals in self.required_vmsss.items():
                threading.Thread(target=self._thr_scale_machine_pool, args=(vals["tag"],)).start()

        # Check the machine pools every 5 minutes
        threading.Timer(300, self._thr_machine_pool_monitor).start()

    def _set_vmss_stage(self):
        """
        Ready. Set. Action! Set the stage for the VMSSs
        """
        global machine_pools
        global is_platform_scaling

        matched_tags = set()
        # Check that each provided gallery image is valid
        for gallery_image_name in self.options.az_with_vmss.gallery_image_names:
            matched_tag = next((tag for tag in self.options.az_with_vmss.supported_os_tags if tag in gallery_image_name), None)

            # Confirm that the provided gallery image names match self.options.az_with_vmss.supported_os_tags
            if not matched_tag:
                raise CuckooConfigurationError("Gallery image name '%s' does not contain any of %s" %
                                               (gallery_image_name, self.options.az_with_vmss.supported_os_tags))

            # Confirm that only a single image is linked to a supported OS tag
            elif matched_tag and matched_tag in matched_tags:
                raise CuckooConfigurationError("Gallery image name '%s' contains a tag '%s' that has already "
                                               "been represented." % (gallery_image_name, matched_tag))
            else:
                matched_tags.add(matched_tag)

        # Now assign the gallery image to the VMSS
        for gallery_image_name in self.options.az_with_vmss.gallery_image_names:
            try:
                gallery_image = Azure._azure_api_call(
                    self.options.az_with_vmss.group,
                    self.options.az_with_vmss.gallery_name,
                    gallery_image_name,
                    operation=self.compute_client.gallery_images.get
                )
            except CuckooMissingMachineError:
                raise CuckooConfigurationError("Gallery image %s does not exist" % gallery_image_name)

            # Map the Image Reference to the VMSS
            tag = next(tag for tag in self.options.az_with_vmss.supported_os_tags if tag in gallery_image_name)
            vmss = next(vmss for vmss in self.required_vmsss.keys() if tag in vmss)
            self.required_vmsss[vmss]["tag"] = tag
            self.required_vmsss[vmss]["image"] = models.ImageReference(id=gallery_image.id)

            # These are specific OS/platform values for Azure's VirtualMachineScaleSetOSDisk
            if Azure.WINDOWS_TAG_PREFIX in tag:
                self.required_vmsss[vmss]["os"] = "Windows"
            elif Azure.LINUX_TAG_PREFIX in tag:
                self.required_vmsss[vmss]["os"] = "Linux"
            else:
                raise CuckooConfigurationError("Tag '%s' does not have a valid tag prefix from %s" %
                                               (tag, Azure.VALID_TAG_PREFIXES))

        # All required VMSSs must have an image reference, tag and os
        for required_vmss_name, required_vmss_values in self.required_vmsss.items():
            if required_vmss_values["image"] is None:
                raise CuckooConfigurationError("The VMSS '%s' does not have an image reference." % required_vmss_name)
            elif required_vmss_values["tag"] is None:
                raise CuckooConfigurationError("The VMSS '%s' does not have an tag." % required_vmss_name)
            elif required_vmss_values["os"] is None:
                raise CuckooConfigurationError("The VMSS '%s' does not have an OS value." % required_vmss_name)

        # Get all VMSSs in Resource Group
        existing_vmsss = Azure._azure_api_call(
            self.options.az_with_vmss.group,
            operation=self.compute_client.virtual_machine_scale_sets.list
        )

        # Delete incorrectly named VMSSs or mark them as existing
        for vmss in existing_vmsss:

            # If a VMSS does not have any tags or does not have the tag that we use to indicate that it is used for
            # Cuckoo (AUTO_SCALE_CUCKOO key-value pair), ignore
            if not vmss.tags or not vmss.tags.get(Azure.AUTO_SCALE_CUCKOO_KEY) == Azure.AUTO_SCALE_CUCKOO_VALUE:

                # Unless! They have one of the required names of the VMSSs that we are going to create
                if vmss.name in self.required_vmsss.keys():
                    async_delete_vmss = Azure._azure_api_call(
                        self.options.az_with_vmss.group,
                        vmss.name,
                        custom_poller=ARM_POLLER,
                        operation=self.compute_client.virtual_machine_scale_sets.delete
                    )
                    _ = self._handle_poller_result(async_delete_vmss)
                # NEXT
                continue

            # The VMSS has tags and the tags include the AUTO_SCALE_CUCKOO key-value pair
            if vmss.name in self.required_vmsss.keys():
                required_vmss = self.required_vmsss[vmss.name]

                # Note that the VMSS exists and that we do not need to create another one
                required_vmss["exists"] = True

                # This flag is used to determine if we have to update the VMSS
                update_vmss = False

                # Check if image reference is out-of-date with the one in the configuration
                if required_vmss["image"].id != vmss.virtual_machine_profile.storage_profile.image_reference.id:
                    # If so, update it
                    update_vmss = True
                    vmss.virtual_machine_profile.storage_profile.image_reference.id = required_vmss["image"].id

                # Check if the capacity of VMSS matches the initial pool size from the configuration
                if vmss.sku.capacity != self.options.az_with_vmss.initial_pool_size:
                    # If no, update it
                    update_vmss = True
                    vmss.sku.capacity = self.options.az_with_vmss.initial_pool_size

                # Initialize key-value pair for VMSS with specific details
                machine_pools[vmss.name] = {
                    "size": int(vmss.sku.capacity),
                    "is_scaling": False,
                    "is_scaling_down": False,
                    "wait": False
                }

                if update_vmss:
                    update_vmss_image = Azure._azure_api_call(
                        self.options.az_with_vmss.group,
                        vmss.name,
                        vmss,
                        custom_poller=ARM_POLLER,
                        operation=self.compute_client.virtual_machine_scale_sets.update
                    )
                    _ = self._handle_poller_result(update_vmss_image)
            else:
                # VMSS does not have the required name but has the tag that we associate with being a
                # correct VMSS
                Azure._azure_api_call(
                    self.options.az_with_vmss.group,
                    vmss.name,
                    operation=self.compute_client.virtual_machine_scale_sets.delete
                )

        try:
            self.subnet_id = Azure._azure_api_call(
                self.options.az_with_vmss.group,
                self.options.az_with_vmss.vnet,
                self.options.az_with_vmss.subnet,
                operation=self.network_client.subnets.get,
            ).id  # note the id attribute here
        except CuckooMissingMachineError:
            raise CuckooConfigurationError("Subnet '%s' does not exist in Virtual Network '%s'" % (
                self.options.az_with_vmss.subnet, self.options.az_with_vmss.vnet))

        # Create required VMSSs that don't exist yet
        vmss_creation_threads = []
        vmss_reimage_threads = []
        for vmss, vals in self.required_vmsss.items():
            if vals["exists"]:
                # Reimage VMSS!
                thr = threading.Thread(
                    target=self._thr_reimage_vmss,
                    args=(vmss, vals["tag"],))
                vmss_reimage_threads.append(thr)
                thr.start()
            else:
                # Create VMSS!
                thr = threading.Thread(
                    target=self._thr_create_vmss,
                    args=(vmss, vals["image"], vals["os"], vals["tag"],))
                vmss_creation_threads.append(thr)
                thr.start()

        # Wait for everything to complete!
        for thr in vmss_reimage_threads + vmss_creation_threads:
            thr.join()

        # Initialize the platform scaling state monitor
        is_platform_scaling = {
            Azure.WINDOWS_PLATFORM: False,
            Azure.LINUX_PLATFORM: False
        }

    def start(self, label, task):
        # NOTE: Machines are always started. ALWAYS
        pass

    def stop(self, label):
        """
        If the VMSS is in the "scaling-down" state, delete machine,
        otherwise reimage it.
        @param label: virtual machine label
        @return: End method call
        """
        log.debug("Stopping machine '%s'" % label)
        # Parse the tag and instance id out to confirm which VMSS to modify
        vmss_name, instance_id = label.split("_")
        # Boolean flag that indicates if Azure is in an error state and reimage commands are timing out
        reimage_timed_out = False
        # Bang on the Azure API until it submits to our whims
        start_time = time.time()
        while True:
            if (time.time() - start_time) > AZURE_TIMEOUT:
                log.error("%s refuses to cooperate, deleting from database and leaving machine in VMSS." % label)
                self._delete_machine_from_db(label)
                break
            if not machine_pools[vmss_name]["is_scaling_down"]:
                try:
                    # TODO: replace this with a batch reimaging when throughput reaches a certain level, either will work:
                    # async_reimage_some = compute_client.virtual_machine_scale_sets.reimage_all(
                    #     resource_group,
                    #     vmss_name,
                    #     instance_ids,
                    #     polling=ARMPolling(1),
                    # )
                    # async_reimage_some = compute_client.virtual_machine_scale_sets.reimage(
                    #     resource_group,
                    #     vmss_name,
                    #     instance_ids=instance_ids,
                    #     polling=ARMPolling(1),
                    # )
                    async_reimage_machine = Azure._azure_api_call(
                        self.options.az_with_vmss.group,
                        vmss_name,
                        instance_id,
                        custom_poller=ARM_POLLER,
                        operation=self.compute_client.virtual_machine_scale_set_vms.reimage
                    )
                except Exception as exc:
                    if "InvalidParameter" in repr(exc):
                        # A reimaged VM cannot be reimaged again. It could still be currently reimaging, despite
                        # reimage.result() returning a value. It could also be deleted, so let's check.
                        if not self._machine_exists(vmss_name, instance_id):
                            log.warning("Machine %s does not exist anymore. Deleting from DB." % label)
                            self._delete_machine_from_db(label)
                            break
                        # Sleep a minute, until Azure gets its act together
                        time.sleep(60)
                        log.debug("Let's try reimaging/deleting %s again!" % label)
                        continue
                    elif any(error in repr(exc) for error in ["AllocationFailed", "DisallowedResourceOperation", "BadRequest"]):
                        # Azure has failed "updating" the machine, therefore, just delete it and move on
                        self._delete_machine_from_db(label)
                        # Attempt to delete it from the VMSS as well
                        _ = self._delete_machine_from_vmss(vmss_name, instance_id)
                        break
                    else:
                        raise
                try:
                    # We wait because we want the machine to be fresh before another task is assigned to it
                    _ = self._handle_poller_result(async_reimage_machine)
                    log.debug("Reimaging %s took %ss" % (label, time.time()-start_time))
                    break
                # TODO: if reimage takes 300s, then delete as it will cause more harm than good
                except CuckooMachineError as exc:
                    # Odds are the reimage command timed out, so set flag to true
                    reimage_timed_out = True
                    log.warning("Unable to reimage %s due to %s. Deleting from database and VMSS." % (label, repr(exc)))
                    self._delete_machine_from_db(label)
                    # Attempt to delete it from the VMSS as well
                    _ = self._delete_machine_from_vmss(vmss_name, instance_id)
                    break
            else:
                is_machine_deleted = self._delete_machine_from_vmss(vmss_name, instance_id)
                if is_machine_deleted:
                    # We don't care when this async_delete_machine finishes
                    self._delete_machine_from_db(label)
                    break
                else:
                    # Sleep a minute, until Azure gets its act together
                    time.sleep(60)
                    log.debug("Let's try reimaging/deleting %s again!" % label)
                    continue

        if reimage_timed_out:
            # Grab the tag from the VMSS name
            tag = vmss_name.split("-")[2]
            # Check remaining relevant machines in database, if 0, then scale!
            relevant_machines = self._get_relevant_machines(tag)
            if len(relevant_machines) == 0:
                global machine_pools
                # This is so that no thread will mess with this VMSS while we try to recreate it
                machine_pools[vmss_name]["is_scaling"] = True
                log.debug("There are no relevant machines for %s available because Azure has failed us. Delete the VMSS, create a new one and SCALE!" % vmss_name)
                async_delete_vmss = Azure._azure_api_call(
                    self.options.az_with_vmss.group,
                    vmss_name,
                    custom_poller=ARM_POLLER,
                    operation=self.compute_client.virtual_machine_scale_sets.delete
                )
                _ = self._handle_poller_result(async_delete_vmss)
                log.debug("Successfully deleted %s. Now to create a new VMSS with the same configurations." % vmss_name)
                vals = self.required_vmsss[vmss_name]
                self._thr_create_vmss(vmss_name, vals["image"], vals["os"], vals["tag"])
                log.debug("Successfully created %s. Now to SCALE!" % vmss_name)
                threading.Thread(target=self._thr_scale_machine_pool, args=(tag,)).start()

    def availables(self, label=None, platform=None, tags=None):
        if all(param is None for param in [label, platform, tags]):
            return super(Azure, self).availables()
        else:
            return self._get_specific_availables(label=label, platform=platform, tags=tags)

    def _get_specific_availables(self, label=None, platform=None, tags=None):
        session = self.db.Session()
        try:
            machines = session.query(Machine)
            # Note that label > platform > tags
            if label:
                machines = machines.filter_by(locked=False).filter_by(label=label)
            elif platform:
                machines = machines.filter_by(locked=False).filter_by(platform=platform)
            elif tags:
                for tag in tags:
                    # If VMSS is in the "wait" state, then WAIT
                    vmss_name = next(name for name, vals in self.required_vmsss.items() if vals["tag"] == tag)
                    if machine_pools[vmss_name]["wait"]:
                        log.debug("Machinery is not ready yet...")
                        return 0
                    machines = machines.filter_by(locked=False).filter(Machine.tags.any(name=tag))
            return machines.count()
        except SQLAlchemyError as e:
            log.exception("Database error getting specific available machines: {0}".format(e))
            return 0
        finally:
            session.close()

    def acquire(self, machine_id=None, platform=None, tags=None):
        """
        Overloading abstracts.py:acquire() to utilize the auto-scale option.
        @param machine_id: the name of the machine to be acquired
        @param platform: the platform of the machine's operating system to be acquired
        @param tags: any tags that are associated with the machine to be acquired
        @return: dict representing machine object from DB
        """
        base_class_return_value = super(Azure, self).acquire(
            machine_id=machine_id,
            platform=platform,
            tags=tags
        )
        if base_class_return_value and base_class_return_value.name:
            # Make sure that machine_id follows naming format Azure.VMSS_NAME_FORMAT
            vmss_name, instance_id = base_class_return_value.name.split("_")
            requested_type = vmss_name.split("-")[2]

            # Get the VMSS name by the tag
            vmss_name = next(name for name, vals in self.required_vmsss.items() if vals["tag"] == requested_type)
            if not machine_pools[vmss_name]["is_scaling"]:
                # Start it and forget about it
                threading.Thread(target=self._thr_scale_machine_pool, args=(requested_type, True if platform else False)).start()

        return base_class_return_value

    def _add_machines_to_db(self, vmss_name, vmss_tag):
        """
        Adding machines to database that did not exist there before.
        @param vmss_name: the name of the VMSS to be queried
        @param vmss_tag: the OS tag to be added to the machine's "tags"
        """
        try:
            log.debug("Adding machines to database for %s." % vmss_name)
            # We don't want to re-add machines! Therefore, let's see what we're working with
            machines_in_db = self.db.list_machines()
            db_machine_labels = [machine.label for machine in machines_in_db]
            # We want to avoid collisions where the IP is already associated with a machine
            db_machine_ips = [machine.ip for machine in machines_in_db]

            # Get all VMs in the VMSS
            paged_vmss_vms = Azure._azure_api_call(
                self.options.az_with_vmss.group,
                vmss_name,
                operation=self.compute_client.virtual_machine_scale_set_vms.list
            )

            # Get all network interface cards for the machines in the VMSS
            paged_vmss_vm_nics = Azure._azure_api_call(
                self.options.az_with_vmss.group,
                vmss_name,
                operation=self.network_client.network_interfaces.list_virtual_machine_scale_set_network_interfaces
            )

            # Turn the Paged result into a list
            vmss_vm_nics = [vmss_vm_nic for vmss_vm_nic in paged_vmss_vm_nics]

            # This will be used if we are in the initializing phase of the system
            ready_vmss_vm_threads = []
            for vmss_vm in paged_vmss_vms:
                if vmss_vm.name in db_machine_labels:
                    # Don't add it if it already exists!
                    continue
                # According to Microsoft, the OS type is...
                os_type = vmss_vm.storage_profile.os_disk.os_type
                # Extract the platform str
                platform = str(os_type).split(".")[1]

                if not vmss_vm.network_profile:
                    log.error("%s does not have a network profile" % vmss_vm.name)
                    continue

                vmss_vm_nic = next((vmss_vm_nic for vmss_vm_nic in vmss_vm_nics
                                   if vmss_vm.network_profile.network_interfaces[0].id.lower() == vmss_vm_nic.id.lower()), None)
                if not vmss_vm_nic:
                    log.error("%s does not match any NICs in %s" % (vmss_vm.network_profile.network_interfaces[0].id.lower(), [vmss_vm_nic.id.lower() for vmss_vm_nic in vmss_vm_nics]))
                    continue
                # Sets "new_machine" object in configuration object to
                # avoid raising an exception.
                setattr(self.options, vmss_vm.name, {})

                # Adding the OS tag to tags, so that we can query machines by it later
                tags = vmss_tag

                private_ip = vmss_vm_nic.ip_configurations[0].private_ip_address
                if private_ip in db_machine_ips:
                    log.error("The IP %s is already associated with a machine in the DB. Moving on..." % private_ip)
                    continue

                # Add machine to DB.
                # TODO: What is the point of name vs label?
                self.db.add_machine(
                    name=vmss_vm.name,
                    label=vmss_vm.name,
                    ip=private_ip,
                    platform=platform,
                    options=self.options.az_with_vmss.options,
                    tags=tags,
                    interface=self.options.az_with_vmss.interface,
                    snapshot=vmss_vm.storage_profile.image_reference.id,
                    resultserver_ip=self.options.az_with_vmss.resultserver_ip,
                    resultserver_port=self.options.az_with_vmss.resultserver_port
                )
                # When we aren't initializing the system, the machine will immediately become available in DB
                # When we are initializing, we're going to wait for the machine to be have the Cuckoo agent all set up
                if self.initializing:
                    thr = threading.Thread(target=Azure._thr_wait_for_ready_machine, args=(vmss_vm.name, private_ip,))
                    ready_vmss_vm_threads.append(thr)
                    thr.start()

            if self.initializing:
                for thr in ready_vmss_vm_threads:
                    try:
                        thr.join()
                    except CuckooGuestCriticalTimeout:
                        raise
        except Exception as e:
            log.error(repr(e))

    def _delete_machines_from_db_if_missing(self, vmss_name):
        """
        Delete machine from database if it does not exist in the VMSS.
        @param vmss_name: the name of the VMSS to be queried
        """
        log.debug("Deleting machines from database if they do not exist in the VMSS.")
        # Get all VMs in the VMSS
        paged_vmss_vms = Azure._azure_api_call(
            self.options.az_with_vmss.group,
            vmss_name,
            operation=self.compute_client.virtual_machine_scale_set_vms.list
        )

        # Turn the Paged result into a list
        vmss_vm_names = [vmss_vm.name for vmss_vm in paged_vmss_vms]

        for machine in self.db.list_machines():
            # If machine entry in database is part of VMSS but machine in VMSS does not exist, delete
            if vmss_name in machine.label and machine.label not in vmss_vm_names:
                self._delete_machine_from_db(machine.label)

    def _delete_machines_from_db_by_list(self, machine_names):
        """
        Delete machines from database by passing it a list.
        @param machine_names: the list of machines to be deleted
        """
        for machine_name in machine_names[:]:
            machine = self.db.view_machine(machine_name)
            # Only delete a machine if it is unlocked
            if not machine.locked:
                self._delete_machine_from_db(machine_name)
            else:
                # Remove the machine name from the list so that it is not deleted in Azure
                machine_names.remove(machine_name)

    def _delete_machine_from_db(self, machine_name):
        """
        Implementing machine deletion from Cuckoo's database.
        This was not implemented in database.py, so implemented here in the machinery
        TODO: move this method to database.py
        @param machine_name: the name of the machine to be deleted
        @return: End method call
        """
        session = self.db.Session()
        try:
            machine = session.query(Machine).filter_by(label=machine_name).first()
            if machine:
                session.delete(machine)
                session.commit()
            else:
                log.warning("%s does not exist in the database." % machine_name)
        except SQLAlchemyError as exc:
            log.debug("Database error removing machine: '%s'.", exc)
            session.rollback()
            return
        finally:
            session.close()

    @staticmethod
    def _thr_wait_for_ready_machine(machine_name, machine_ip):
        """
        Static method that is used to determine if the agent is running on a machine yet.
        @param machine_name: the name of the machine waited for. NOTE param is only used for logging.
        @param machine_ip: the IP of the machine we are waiting for.
        @return: End method call
        """
        # Majority of this code is copied from cuckoo/core/guest.py:GuestManager.wait_available()
        start = time.time()
        end = start + config("cuckoo:timeouts:vm_state")
        while True:
            try:
                socket.create_connection((machine_ip, CUCKOO_GUEST_PORT), 1).close()
                # We did it!
                break
            except socket.timeout:
                log.debug("%s: Initializing...", machine_name)
            except socket.error:
                log.debug("%s: Initializing...", machine_name)
            time.sleep(10)

            if time.time() >= end:
                # We didn't do it :(
                self._delete_machine_from_db(machine_name)
                raise CuckooGuestCriticalTimeout(
                    "Machine %s: the guest initialization hit the critical "
                    "timeout, analysis aborted." % machine_name
                )
        log.debug("Machine %s was created and available in %9.3fs", machine_name, time.time() - start)

    @staticmethod
    def _azure_api_call(*args, **kwargs):
        """
        This method is used as a common place for all Azure API calls
        @param args: any argument that an Azure API call takes
        @param kwargs: the API call operation, and sometimes tags
        @raise CuckooMachineError: if there is a problem with the Azure call
        @return: dict containing results of API call
        """
        # I figured this was the most concrete way to guarantee that an API method was being passed
        if not kwargs["operation"]:
            raise Exception("kwargs in _azure_api_call requires 'operation' parameter.")
        operation = kwargs["operation"]

        # Note that tags is a special keyword parameter in some operations
        tags = kwargs.get("tags", None)

        # This is used for logging
        api_call = "%s(%s)" % (operation, args)

        # Note that we are using a custom poller for some operations
        custom_poller = kwargs.get("custom_poller", True)

        try:
            log.debug("Trying %s", api_call)
            results = operation(*args, tags=tags, polling=custom_poller)
        except Exception as exc:
            # For ClientRequestErrors, they do not have the attribute 'error'
            error = exc.error.error if getattr(exc, "error", False) else exc
            log.warning("Failed to %s due to the Azure error '%s': '%s'.",
                        api_call, error, exc.message)
            if "NotFound" in repr(exc) or exc.status_code == 404:
                # Note that this exception is used to represent if an Azure resource
                # has not been found, not just machines
                raise CuckooMissingMachineError("%s:%s" % (error, exc.message))
            else:
                raise CuckooMachineError("%s:%s" % (error, exc.message))
        if type(results) == LROPoller:
            # Log the subscription limits
            headers = results._response.headers
            log.debug("API Charge: %s; Remaining Calls: %s" % (headers["x-ms-request-charge"], headers['x-ms-ratelimit-remaining-resource']))
        return results

    def _thr_create_vmss(self, vmss_name, vmss_image_ref, vmss_image_os, vmss_tag):
        """
        Creates a Virtual Machine Scale Set
        @param vmss_name: The name of the VMSS to be created
        @param vmss_image_ref: The image reference to be used for the VMSS
        @param vmss_image_os: The platform of the image
        @param vmss_tag: the tag used that represents the OS image
        """
        global machine_pools

        vmss_managed_disk = models.VirtualMachineScaleSetManagedDiskParameters(
            storage_account_type=self.options.az_with_vmss.storage_account_type
        )
        vmss_os_disk = models.VirtualMachineScaleSetOSDisk(
            create_option="FromImage",
            os_type=vmss_image_os,
            managed_disk=vmss_managed_disk,
            # Ephemeral disk time
            caching="ReadOnly",
            diff_disk_settings=models.DiffDiskSettings(option="Local")
        )
        vmss_storage_profile = models.VirtualMachineScaleSetStorageProfile(
            image_reference=vmss_image_ref,
            os_disk=vmss_os_disk,
        )
        vmss_dns_settings = models.VirtualMachineScaleSetNetworkConfigurationDnsSettings(
            dns_servers=[self.options.az_with_vmss.resultserver_ip]
        )
        vmss_ip_config = models.VirtualMachineScaleSetIPConfiguration(
            name="vmss_ip_config",
            subnet=models.ApiEntityReference(id=self.subnet_id),
            private_ip_address_version="IPv4",
        )
        vmss_network_config = models.VirtualMachineScaleSetNetworkConfiguration(
            name="vmss_network_config",
            dns_settings=vmss_dns_settings,
            ip_configurations=[vmss_ip_config],
            primary=True
        )
        vmss_network_profile = models.VirtualMachineScaleSetNetworkProfile(
            network_interface_configurations=[vmss_network_config]
        )
        vmss_vm_profile = models.VirtualMachineScaleSetVMProfile(
            storage_profile=vmss_storage_profile,
            network_profile=vmss_network_profile,
            # Note: The following key value pairs are for Azure spot instances
            priority=models.VirtualMachinePriorityTypes.spot,
            eviction_policy=models.VirtualMachineEvictionPolicyTypes.delete,
            # Note: This value may change depending on your needs.
            billing_profile=models.BillingProfile(max_price=float(-1))
        )
        vmss = models.VirtualMachineScaleSet(
            location=self.options.az_with_vmss.region_name,
            sku=models.Sku(name=self.options.az_with_vmss.instance_type, capacity=self.options.az_with_vmss.initial_pool_size),
            upgrade_policy=models.UpgradePolicy(mode="Manual"),
            virtual_machine_profile=vmss_vm_profile,
            overprovision=False,
            # When true this limits the scale set to a single placement group, of max size 100 virtual machines.
            single_placement_group=False,
            tags=Azure.AUTO_SCALE_CUCKOO_TAG,
            scale_in_policy=models.ScaleInPolicy(rules=[models.VirtualMachineScaleSetScaleInRules.newest_vm])
        )
        async_vmss_creation = Azure._azure_api_call(
            self.options.az_with_vmss.group,
            vmss_name,
            vmss,
            custom_poller=ARM_POLLER,
            operation=self.compute_client.virtual_machine_scale_sets.create_or_update
        )
        _ = self._handle_poller_result(async_vmss_creation)

        # Initialize key-value pair for VMSS with specific details
        machine_pools[vmss_name] = {
            "size": self.options.az_with_vmss.initial_pool_size,
            "is_scaling": False,
            "is_scaling_down": False,
            "wait": False
        }
        self._add_machines_to_db(vmss_name, vmss_tag)

    def _thr_reimage_vmss(self, vmss_name, tag):
        """
        Reimage the VMSS
        @param vmss_name: the name of the VMSS to be reimage
        @param tag: the tag used that represents the OS image
        """
        # Reset all machines via reimage_all
        try:
            async_reimage_all = Azure._azure_api_call(
                self.options.az_with_vmss.group,
                vmss_name,
                custom_poller=ARM_POLLER,
                operation=self.compute_client.virtual_machine_scale_sets.reimage_all
            )
            _ = self._handle_poller_result(async_reimage_all)
        except CuckooMachineError as e:
            # Possible error: 'BadRequest': 'The VM {id} creation in Virtual Machine Scale Set {vmss-name} with
            # ephemeral disk is not complete. Please trigger a restart if required.'
            if "BadRequest" in repr(e):
                async_restart_vmss = Azure._azure_api_call(
                    self.options.az_with_vmss.group,
                    vmss_name,
                    custom_poller=ARM_POLLER,
                    operation=self.compute_client.virtual_machine_scale_sets.restart
                )
                _ = self._handle_poller_result(async_restart_vmss)
            else:
                log.error(repr(e))
                raise
        self._add_machines_to_db(vmss_name, tag)

    def _thr_scale_machine_pool(self, tag, per_platform=False):
        """
        Expand/Reduce the machine pool based on the number of queued relevant tasks
        @param tag: the OS tag of the machine pool to be scaled
        @param per_platform: A boolean flag indicating that we should scale machine pools "per platform" vs. "per tag"
        @return: Ends method call
        """
        global machine_pools
        global is_platform_scaling

        platform = None
        if per_platform and Azure.WINDOWS_TAG_PREFIX in tag:
            platform = Azure.WINDOWS_PLATFORM
        elif per_platform and Azure.LINUX_TAG_PREFIX in tag:
            platform = Azure.LINUX_PLATFORM

        # If the designated VMSS is already being scaled for the given platform, don't mess with it
        if platform and is_platform_scaling[platform]:
            return

        # Get the VMSS name by the tag
        vmss_name = next(name for name, vals in self.required_vmsss.items() if vals["tag"] == tag)

        # TODO: Remove large try-catch once all bugs have been caught
        # It has been observed that there are times when the is_scaling flag is not returned to False even though
        # scaling has completed. Therefore we need this try-catch to figure out why.
        try:
            # If this VMSS is already being scaled, don't mess with it
            if machine_pools[vmss_name]["is_scaling"]:
                return

            # This is the flag that is used to indicate if the VMSS is being scaled by a thread
            machine_pools[vmss_name]["is_scaling"] = True

            # This is the flag that is used to indicate if a designated VMSS has been selected for a platform and if
            # it is being scaled by a thread
            if platform:
                is_platform_scaling[platform] = True

            relevant_machines = self._get_relevant_machines(tag)
            number_of_relevant_machines = len(relevant_machines)
            machine_pools[vmss_name]["size"] = number_of_relevant_machines
            relevant_task_queue = self._get_number_of_relevant_tasks(tag, platform)

            # The scaling technique we will use is a tweaked version of the Leaky Bucket, where we
            # only scale down if the relevant task queue is empty.

            # If there are no relevant tasks in the queue, scale to the bare minimum pool size
            if relevant_task_queue == 0:
                number_of_relevant_machines_required = self.options.az_with_vmss.initial_pool_size
            else:
                number_of_relevant_machines_required = \
                    int(round(relevant_task_queue * (1 + self.options.az_with_vmss.overprovision / 100)))

            if number_of_relevant_machines_required < self.options.az_with_vmss.initial_pool_size:
                number_of_relevant_machines_required = self.options.az_with_vmss.initial_pool_size
            elif number_of_relevant_machines_required > self.options.az_with_vmss.dynamic_machines_limit:
                number_of_relevant_machines_required = self.options.az_with_vmss.dynamic_machines_limit

            if machine_pools[vmss_name]["size"] == number_of_relevant_machines_required:
                # Check that VMs in DB actually exist in the VMSS. There is a possibility that
                # Azure will delete a machine in a VMSS that has not been used in a while. So the machine_pools value
                # will not be up-to-date
                self._delete_machines_from_db_if_missing(vmss_name)
                # Update the VMSS size accordingly
                machine_pools[vmss_name]["size"] = len(self._get_relevant_machines(tag))
                log.debug("The size of the machine pool %s is already the size that we want" % vmss_name)
                machine_pools[vmss_name]["is_scaling"] = False
                if platform:
                    is_platform_scaling[platform] = False
                return

            # This value will be used for adding or deleting machines from the database
            # NOTE: If you set the VMSS capacity to 4, then delete a VM, the capacity is set to 3 for some reason.
            # Therefore we want to grab the initial capacity from the global variable before machines are deleted,
            # since the vmss.sku.capacity variable is unreliable.
            initial_capacity = machine_pools[vmss_name]["size"]

            # Time to scale down!
            if number_of_relevant_machines_required < initial_capacity:
                # Creating these variables to be used to assist with the scaling down process
                initial_number_of_locked_relevant_machines = len([machine for machine in relevant_machines if machine.locked])
                initial_number_of_unlocked_relevant_machines = number_of_relevant_machines - initial_number_of_locked_relevant_machines

                # The system is at rest when no relevant tasks are in the queue and no relevant machines are locked
                if relevant_task_queue == 0 and initial_number_of_locked_relevant_machines == 0:
                    # The VMSS will scale in via the ScaleInPolicy.
                    machine_pools[vmss_name]["wait"] = True
                    log.debug("System is at rest, scale down %s capacity and delete machines." % vmss_name)
                # System is not at rest, but task queue is 0, therefore set machines in use to delete
                elif relevant_task_queue == 0:
                    machine_pools[vmss_name]["is_scaling_down"] = True
                    start_time = time.time()
                    # Wait until currently locked machines are deleted to the number that we require
                    while number_of_relevant_machines > number_of_relevant_machines_required:
                        # Since we're sleeping 1 second between iterations of this while loop, if there are available
                        # machines waiting to be assigned tasks and a new task comes down the pipe then there will be
                        # no queue and instead the # of locked relevant machines will increase (or unlocked relevant
                        # machines will decrease). Either one indicates that a new task has been submitted and therefore
                        # the "scaling down" process should exit. This is to prevent scaling down and up so often.
                        updated_number_of_locked_relevant_machines = len([machine for machine in relevant_machines if machine.locked])
                        updated_number_of_unlocked_relevant_machines = number_of_relevant_machines - updated_number_of_locked_relevant_machines

                        # We don't want to be stuck in this for longer than the timeout specified
                        if time.time() - start_time > AZURE_TIMEOUT:
                            log.debug("Breaking out of the while loop within the scale down section")
                            break
                        # Get the updated number of relevant machines required
                        relevant_task_queue = self._get_number_of_relevant_tasks(tag)
                        # As soon as a task is in the queue or has been assigned to a machine, we do not want to scale down any more.
                        # Deleting an instance affects the capacity of the VMSS, so we do not need to update it.
                        if relevant_task_queue or \
                                updated_number_of_locked_relevant_machines > initial_number_of_locked_relevant_machines or \
                                updated_number_of_unlocked_relevant_machines < initial_number_of_unlocked_relevant_machines:
                            break
                        # Relaxxxx
                        time.sleep(1)
                        log.debug("Scaling %s down until new task is received. %s -> %s" %
                                  (vmss_name, number_of_relevant_machines, number_of_relevant_machines_required))

                        # Get an updated count of relevant machines
                        relevant_machines = self._get_relevant_machines(tag)
                        number_of_relevant_machines = len(relevant_machines)
                        machine_pools[vmss_name]["size"] = number_of_relevant_machines

                    # No longer scaling down
                    machine_pools[vmss_name]["is_scaling_down"] = False
                    machine_pools[vmss_name]["is_scaling"] = False
                    return
                else:
                    # We only scale down if the relevant task queue is 0
                    machine_pools[vmss_name]["is_scaling"] = False
                    return

            # Update the capacity of the VMSS
            log.debug("Scaling %s size from %s -> %s" % (vmss_name, initial_capacity, number_of_relevant_machines_required))
            vmss = Azure._azure_api_call(
                self.options.az_with_vmss.group,
                vmss_name,
                operation=self.compute_client.virtual_machine_scale_sets.get
            )
            vmss.sku.capacity = number_of_relevant_machines_required
            start_time = time.time()

            try:
                async_update_vmss = Azure._azure_api_call(
                    self.options.az_with_vmss.group,
                    vmss_name,
                    vmss,
                    custom_poller=ARM_POLLER,
                    operation=self.compute_client.virtual_machine_scale_sets.update
                )
                _ = self._handle_poller_result(async_update_vmss)
            except CuckooMachineError as e:
                log.warning(repr(e))
                machine_pools[vmss_name]["wait"] = False
                machine_pools[vmss_name]["is_scaling"] = False
                if platform:
                    is_platform_scaling[platform] = False
                return

            log.debug("The scaling of %s took %ss" % (vmss_name, time.time()-start_time))
            machine_pools[vmss_name]["size"] = number_of_relevant_machines_required

            # Alter the database based on if we scaled up or down
            log.debug("Updated %s capacity: %s; Initial capacity: %s" % (vmss_name, number_of_relevant_machines_required, initial_capacity))
            if number_of_relevant_machines_required > initial_capacity:
                self._add_machines_to_db(vmss_name, tag)
            else:
                self._delete_machines_from_db_if_missing(vmss_name)

            # I release you from your earthly bonds!
            machine_pools[vmss_name]["wait"] = False
            machine_pools[vmss_name]["is_scaling"] = False
            if platform:
                is_platform_scaling[platform] = False
            log.debug("Scaling %s has completed." % vmss_name)
        except Exception as exc:
            machine_pools[vmss_name]["wait"] = False
            machine_pools[vmss_name]["is_scaling"] = False
            if platform:
                is_platform_scaling[platform] = False
            log.error(repr(exc))
            log.debug("Scaling %s has completed with errors." % vmss_name)

    @staticmethod
    def _handle_poller_result(lro_poller_object):
        """
        Provides method of handling Azure tasks that take too long to complete
        @param lro_poller_object: An LRO Poller Object for an Async Azure Task
        """
        start_time = time.time()
        # TODO: Azure disregards the timeout passed to it in most cases, unless it has a custom poller
        try:
            lro_poller_result = lro_poller_object.result(timeout=AZURE_TIMEOUT)
        except Exception as e:
            raise CuckooMachineError(repr(e))
        if (time.time() - start_time) >= AZURE_TIMEOUT:
            raise CuckooMachineError("The task took %s to complete! Bad Azure!" % (time.time() - start_time))
        else:
            return lro_poller_result

    def _get_number_of_relevant_tasks(self, tag, platform=None):
        """
        Returns the number of relevant tasks for a tag or platform
        @param tag: The OS tag used for finding relevant tasks
        @param platform: The platform used for finding relevant tasks
        @return int: The number of relevant tasks for the given tag
        """
        # Getting all tasks in the queue
        tasks = self.db.list_tasks(status=TASK_PENDING)

        # The task queue that will be used to prepare machines will be relative to the virtual
        # machine tag that is targeted in the task (win7, win10, etc) or platform (windows, linux)
        relevant_task_queue = 0

        if not platform:
            for task in tasks:
                for t in task.tags:
                    if t.name == tag:
                        relevant_task_queue += 1
        else:
            for task in tasks:
                if task.platform == platform:
                    relevant_task_queue += 1
        return relevant_task_queue

    def _get_relevant_machines(self, tag):
        """
        Returns the relevant machines for a given tag
        @param tag: The OS tag used for finding relevant machines
        @return list of db.Machine: The machines that are relevant for the given tag
        """
        # The number of relevant machines are those from the list of locked and unlocked machines
        # that have the correct tag in their name
        return [machine for machine in self.db.list_machines() if tag in machine.label]

    def _machine_exists(self, vmss_name, instance_id):
        """
        Returns a boolean that represents if the machine exists
        @param vmss_name: The name of the VMSS
        @param instance_id: The ID of the instance to check if it exists
        @return boolean: Representative of if the machine exists
        @raises Exception: If another exception occurs, raise it up!
        """
        try:
            vmss_vm = Azure._azure_api_call(
                self.options.az_with_vmss.group,
                vmss_name,
                instance_id,
                operation=self.compute_client.virtual_machine_scale_set_vms.get
            )
        except CuckooMissingMachineError:
            return False
        return True

    def _delete_machine_from_vmss(self, vmss_name, instance_id):
        """
        Returns a boolean indicating if operation to delete machine from VMSS was successful
        @param vmss_name: String representing the virtual machine scale set name
        @param instance_id: ID of the machine to be deleted
        @return boolean: Value that represents if operation was successful
        @raises Exception: If another exception occurs, raise it up!
        """
        try:
            # TODO: replace with batch deleting when throughput reaches a certain level
            # async_delete_some = compute_client.virtual_machine_scale_sets.delete_instances(
            #     resource_group,
            #     vmss_name,
            #     instances_to_be_acted_on
            # )
            Azure._azure_api_call(
                self.options.az_with_vmss.group,
                vmss_name,
                instance_id,
                operation=self.compute_client.virtual_machine_scale_set_vms.delete
            )
            return True
        except Exception as exc:
            if any(error in repr(exc) for error in ["Conflict"]):
                return False
            else:
                raise
