# Cuckoo Sandbox

Our industrious oompa loompas worked restlessly to finally bring you this funny little piece of software that goes by the name of [Cuckoo Sandbox](http://www.cuckoobox.org).
Cuckoo is a free software.
It's main goal is to provide you an open source, lightweight, highly customizable solution for your nastiest **malware analysis** needs.

## Requirements

To properly run Cuckoo you'll need what follows:

  * [Python](http://www.python.org)
  * [VirtualBox](http://www.virtualbox.org)
  * [Tcpdump](http://www.tcpdump.org)

## Download

You can download Cuckoo by cloning the Git repository:

    git clone git://github.com/cuckoobox/cuckoo.git
    
Or download the latest tarball at:

[https://github.com/cuckoobox/cuckoo/tarball/master](https://github.com/cuckoobox/cuckoo/tarball/master)

## Launch

Launch Cuckoo with:

    python cuckoo.py
    
This is the output you'll see:

                         _                  
        ____ _   _  ____| |  _ ___   ___    
       / ___) | | |/ ___) |_/ ) _ \ / _ \ 
      ( (___| |_| ( (___|  _ ( |_| | |_| |  
       \____)____/ \____)_| \_)___/ \___/ v0.2
    
     www.cuckoobox.org                                
     Copyright (C) 2010-2011                          
     by Claudio "nex" Guarnieri
    
    [2011-09-08 19:52:56] [Virtual Machine] [Check] Your VirtualBox version is: "4.1.2", good!
    [2011-09-08 19:52:56] [Start Up] Populating virtual machines pool...
    [2011-09-08 19:52:56] [Virtual Machine] Acquired virtual machine with name "Cuckoo_1".
    [2011-09-08 19:52:56] [Virtual Machine] [Infos] Virtual machine "Cuckoo_1" informations:
    [2011-09-08 19:52:56]   \_| Name: Cuckoo_1
    [2011-09-08 19:52:56] 	  | ID: xxxxxxx-xxxx-xxxx
    [2011-09-08 19:52:56] 	  | CPU Count: 1 Core/s
    [2011-09-08 19:52:56] 	  | Memory Size: 192 MB
    [2011-09-08 19:52:56] 	  | VRAM Size: 16 MB
    [2011-09-08 19:52:56] 	  | State: Saved
    [2011-09-08 19:52:56] 	  | Current Snapshot: "Clean & Running"
    [2011-09-08 19:52:56] 	  | MAC Address: 08:00:27:03:13:37
    [2011-09-08 19:52:56] [Start Up] 1 virtual machine/s added to pool.
    [2011-09-08 19:52:56] [Database] [Init] Generated database "cuckoo.db" which didn't exist before.

## Donations
Cuckoo is the result of hours and hours and hours and hours of passionated work from volunteers. If you appreciated our work, you use Cuckoo please consider making a small contribution to our efforts and to the expenses we face, please **Flattr** us:

[![Flattr this git repo](http://api.flattr.com/button/flattr-badge-large.png)](https://flattr.com/submit/auto?user_id=malwr&url=http://github.com/cuckoobox/cuckoo&title=Cuckoo Sandbox&language=en_GB&tags=github&category=software)
