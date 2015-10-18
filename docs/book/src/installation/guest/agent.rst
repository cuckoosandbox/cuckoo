====================
Installing the Agent
====================

From release 0.4 Cuckoo adopts a custom agent that runs inside the Guest and
that handles the communication and the exchange of data with the Host.
This agent is designed to be cross-platform, therefore you should be able
to use it on Windows as well as on Linux and OS X.
In order to make Cuckoo work properly, you'll have to install and start this
agent.

It's very simple.

In the *agent/* directory you will find and *agent.py* file, just copy it
to the Guest operating system (in whatever way you want, perhaps a temporary
shared folder or by downloading it from a Host webserver) and run it.

This will launch the XMLRPC server which will be listening for connections.

On Windows simply launching the script will also spawn a Python window, if
you want to hide it you can rename the file from *agent.py* to **agent.pyw**
which will prevent the window from spawning.

If you want the script to be launched at Windows' boot, just place the file in
the `Startup` folder.

To enable transient shares to be able to copy files into the vm directory and for a lot of other features, the Guest Additions should be installed in the virutal machine.
In case you are running a cmd-line only virtualbox vers.5 with windows you might tries this approach to mount the iso of the GuestAdditions.

xp-32-vm-1 is the name of your virtual machine, the port / device etc. information can be retrieved by the 

vboxmanage showvminfo xp-32-vm-1 

command.

Mount the iso file:

vboxmanage storageattach xp-32-vm-1 --storagectl "IDE" --port 0 --device 1 --type dvddrive --medium /usr/share/virtualbox/VBoxGuestAdditions.iso 

You can then boot into your virtual machine and execute the guest addition setup.
To remove the mounted iso file, execute the following command.

vboxmanage storageattach xp-32-vm-1 --storagectl "IDE" --port 0 --device 1 --type dvddrive --medium emptydrive

For unknown reasons the copyto command seems to be buggy and didn't work for me, so I had to create a transient share.
