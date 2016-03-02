================
Saving the Guest
================

Now you should be ready to save the physical machine to a clean state.
In order for the physical machine manager to work, you must have a way
for physical machines to be returned to a clean state.

Before doing this **make sure you rebooted it softly and that it's currently
running, with Cuckoo's agent running and with Windows fully booted**.

Now you can proceed saving the machine. The way to do it obviously depends on
the imaging software you decided to use.

In development/testing Fog (http://www.fogproject.org/) was used as a platform
to handle re-imaging the physical machines.
However, any re-imaging platform can be used (Clonezilla, Deepfreeze, etc.) to
accomplish this.

If you follow all the below steps properly, your virtual machine should be ready
to be used by Cuckoo.

Fog
===

After installing Fog, you will need to create an image and add an image and a
host to the Fog server.

To add an image to the fog server, open the Image Management window
(\http://<your_fog_server>/fog/management/index.php?node=images)
and click "Create New Image."
Provide the proper inputs for your OS configuration and click "Add"

    .. image:: ../../_images/screenshots/fog_image_management.png
        :align: center

Next you will need to add the host you plan to re-image to Fog.
To add a host, open a web browser and navigate to the Host Management page of
Fog (\http://<your_fog_server>/fog/management/index.php?node=host).
Click "Create New Host."
Provide the proper inputs for your host configuration. Be sure to select the
image you created above from the "Host Image" option, when finished click the
"Add" button.

    .. image:: ../../_images/screenshots/fog_host_management.png
        :align: center

At this point you should be ready to take an image from the guest machine.
In order to take an image you will need to navigate to the Task Management page
and list all hosts (\http://<your_fog_server>/fog/management/index.php?node=tasks&sub=listhosts).
From here you should be able to click the Upload icon (Green up arrow), which
should instantly add a task to the queue to take an image.
Now you should reboot your Cuckoo guest image and it should PXE boot into Fog
and capture the base image from the cuckoo guest.

After you have successfully taken an image of the guest machine, you can use
that image as one to deploy to the Cuckoo physical sandbox as needed.
It is recommended to use a scheduled task to accomplish this.
In order to create a scheduled task to re-image sandboxes, navigate to the Host
Management page on Fog (http://<your_fog_server>/fog/management/index.php?node=host&sub=list).
Then click "Download" the machine you wish to schedule the re-image task for.
From this menu, select "Schedule Cron-style Deployment" and put in the values
you wish for the schedule to apply to (``*/5 * * * *``) in the case shown in the
screenshot below, but you may need to tweak these times for your environment.

    .. image:: ../../_images/screenshots/fog_scheduled_job.png
        :align: center


Setup using VMWare (Bonus!)
===========================

Traditionally Cuckoo requires to be running some sort of virtualization software
(e.g. VMware, Virtualbox, etc).
The physical machine manager will also work with other virtual machines, so long
as they are configured to revert to a snapshot on shutdown/reboot, and running
the agent.py script.
A use case for this functionality would be to run the cuckoo server and the
guest sandboxes each in their own virtual machine on a single host, allowing for
development/testing of Cuckoo without requiring a dedicated Linux host.
