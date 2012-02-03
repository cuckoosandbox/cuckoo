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
       \____)____/ \____)_| \_)___/ \___/ v0.3.2

     www.cuckoobox.org
     Copyright (C) 2010-2012

    [2012-01-31 12:52:13,295] [Core.Init] INFO: Started.
    [2012-01-31 12:52:14,656] [VirtualMachine.Check] INFO: Your VirtualBox version is: "4.1.8", good!
    [2012-01-31 12:52:14,657] [Core.Init] INFO: Populating virtual machines pool...
    [2012-01-31 12:52:15,612] [VirtualMachine.Restore] INFO: Virtual machine "Cuckoo1" successfully restored to current snapshot.
    [2012-01-31 12:52:15,896] [VirtualMachine.Infos] INFO: Virtual machine "Cuckoo1" information:
    [2012-01-31 12:52:15,897] [VirtualMachine.Infos] INFO: 	\_| Name: Cuckoo1
    [2012-01-31 12:52:15,897] [VirtualMachine.Infos] INFO: 	  | ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    [2012-01-31 12:52:15,898] [VirtualMachine.Infos] INFO: 	  | CPU Count: 1 Core/s
    [2012-01-31 12:52:15,899] [VirtualMachine.Infos] INFO: 	  | Memory Size: 192 MB
    [2012-01-31 12:52:15,899] [VirtualMachine.Infos] INFO: 	  | VRAM Size: 16 MB
    [2012-01-31 12:52:15,899] [VirtualMachine.Infos] INFO: 	  | State: Saved
    [2012-01-31 12:52:15,900] [VirtualMachine.Infos] INFO: 	  | Current Snapshot: "Clean"
    [2012-01-31 12:52:15,900] [VirtualMachine.Infos] INFO: 	  | MAC Address: 08:00:27:XX:XX:XX
    [2012-01-31 12:52:15,901] [Core.Init] INFO: 1 virtual machine/s added to pool.
    [2012-01-31 12:52:16,049] [Database.Init] INFO: Generated database "db/cuckoo.db" which didn't exist before.

Now Cuckoo is ready to run and it's waiting for submissions.

