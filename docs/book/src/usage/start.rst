===============
Starting Cuckoo
===============

To start Cuckoo use the command::

    $ python cuckoo.py

Make sure to run it inside Cuckoo's root directory.

You will get an output similar to this::

                         _                  
        ____ _   _  ____| |  _ ___   ___    
       / ___) | | |/ ___) |_/ ) _ \ / _ \ 
      ( (___| |_| ( (___|  _ ( |_| | |_| |  
       \____)____/ \____)_| \_)___/ \___/ v0.3

     www.cuckoobox.org
     Copyright (C) 2010-2011

    [2011-12-18 17:43:06,343] [Core.Init] INFO: Started.
    [2011-12-18 17:43:06,834] [VirtualMachine.Check] INFO: Your VirtualBox version is: "4.1.6", good!
    [2011-12-18 17:43:06,834] [Core.Init] INFO: Populating virtual machines pool...
    [2011-12-18 17:43:06,840] [VirtualMachine.Infos] INFO: Virtual machine "Cuckoo1" information:
    [2011-12-18 17:43:06,841] [VirtualMachine.Infos] INFO: 	\_| Name: Cuckoo1
    [2011-12-18 17:43:06,841] [VirtualMachine.Infos] INFO: 	  | ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    [2011-12-18 17:43:06,841] [VirtualMachine.Infos] INFO: 	  | CPU Count: 1 Core/s
    [2011-12-18 17:43:06,841] [VirtualMachine.Infos] INFO: 	  | Memory Size: 192 MB
    [2011-12-18 17:43:06,841] [VirtualMachine.Infos] INFO: 	  | VRAM Size: 16 MB
    [2011-12-18 17:43:06,841] [VirtualMachine.Infos] INFO: 	  | State: Saved
    [2011-12-18 17:43:06,842] [VirtualMachine.Infos] INFO: 	  | Current Snapshot: "Clean"
    [2011-12-18 17:43:06,842] [VirtualMachine.Infos] INFO: 	  | MAC Address: 08:00:27:XX:XX:XX
    [2011-12-18 17:43:06,842] [Core.Init] INFO: 1 virtual machine/s added to pool.
    [2011-12-18 17:43:07,045] [Database.Init] INFO: Generated database "db/cuckoo.db" which didn't exist before.

Now Cuckoo is ready to run and it's listening for submissions.

