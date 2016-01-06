======================================================================================
Document Cuckoo VMI, XEN. Made by Cuckoo VMI project group HvA (Nick, Rob, Tom, Tomas)
======================================================================================

XEN Hypervisor
--------------

Within the project we are going to use XEN to ensure that Cuckoo Sandbox 
cannot be detected as a malware analysis software anymore. 
This means there has to be a ‘layer’ (XEN) around the Cuckoo Sandbox which 
ensures Cuckoo Sandbox cannot be detected by malware anymore, when analyzing malware. 
Firstly it is important to know what exactly XEN Hypervisor is and how and for what is is used. 
We will explain this in this chapter.

XEN is a free, open source and virtual machine monitor (VMM) or hypervisor for x86-, 
Itanium (microprocessor) and PowerPC (processorarchitecture)-systems. 
It is software which runs on a host-operating system which makes it possible to let multiple 
guest-operating systems run on the same time on the same hardware. 
XEN provides secured isolation, management of resources, quality assurance and 
live migrations of Virtual Machines. 
On older computer systems operating systems have to be changed on a specific way 
before they can run XEN (even though the compatibility for user applications remains). 
If we want to visualize how XEN works, it would look something like `this`_.

	* XEN Hypervisor is a layer of software, consisting of approximately 150.000 lines of code, 
	  which runs directly on the hardware. This layer is responsible for managing the CPU and memory. 
	  It is the first program that runs after the bootloader ends. 
	  The hypervisor itself has no knowledge of I/O functions like the network or storage.
	* Guest Domains/Virtual Machines are virtual environments, where each environment has its 
	  own operating system and various applications. The Hypervisor supports two different virtual modes: 
	  paravirtualization (PV) and hardware supportive or complete virtualisation (CV). 
	  Both can be used simultaneously on a Hypervisor. 
	  Guest VMs are completely isolated from the hardware, in other words, 
	  they do not have access to the hardware or I/O functionality. 
	  These Guest VMs are also called ‘unprivileged domains’ (DomU).
	* Control Domain (of Domain 0) is a specialized Virtual Machine which has access to the 
	  hardware and the I/O functionalities, and communicates with the other Virtual Machines. 
	  Without Domain 0 XEN cannot be used, because this is the first Virtual Machine which is booted 
	  by the system.
	* Toolstack and Console: Domain 0 has a so called control stack (also known as Toolstack) t
	  that can create, manage and even destroy the Virtual Machine. 
	  This Toolstack has an interface which is usually uses the command line or other graphic interfaces. 

.. _`this`: http://wiki.xen.org/wiki/Xen_Project_Software_Overview

Lib VMI
-------
LibVMI is a C library with Python bindings that makes it easy to monitor the low-level 
details of a running virtual machine by viewing its memory, trapping on hardware events, 
and accessing the vCPU registers. This is called virtual machine introspection. 
This means that it helps you access the memory of a running virtual machine. 
LibVMI provides primitives for accessing this memory using physical or virtual addresses and kernel symbols.
LibVMI also supports accessing memory from a physical memory snapshot, 
which is helpful for debugging or forensic analysis.
In addition to memory access, LibVMI supports memory events. 
Events provide notifications when registered regions of memory are executed, written to, or read. 
Memory events require hypervisor support and are currently only available with Xen. 
LibVMI is designed to run on Linux or Mac OS X. The most used platform is Linux + Xen, 
but the others are well tested and worth using as well. 
LibVMI can provide access to physical memory for any operating system, and access to virtual memory 
and kernel symbols from Windows and Linux. 
The picture shows how `Lib VMI`_ works. You can also see how Lib VMI works together with XEN.

One important thing to mention is that if you want to use XEN with LibVMI, 
that you should first install XEN and then LibVMI. Not the other way around. 

.. _`Lib VMI`: http://libvmi.com/assets/images/access.png

LSASS
-----
LSASS stands for Local Security Authority Subsystem Service. 
It is a process within Windows operating systems that is responsible for enforcing the security policy 
on the system. It verifies users logging on to a Windows computer or server, handles password changes 
and creates access tokens. It also writes to the Windows Security Log. The lsass.exe file is 
located in the directory Windows/System32.
We tried using LSASS to show the Proof of Concept, but it didn’t work for various reasons. 
After this we made a small program to show the Proof of Concept, called magick.exe.

Magick.exe
----------
Magick.exe is a executable made by us. This makes it handy for us to use the proof of concept in a fast way.
The code that the executable contains is::

#include <stdio.h>

int main(int argv, char** argc) {
	while(1) {
		GetTickCount();
		Sleep(1000);

	}

}

This code calls a Windows API, GetTickCount(). We then hook GetTickCount and when GetTickCount 
is called we change the RIP (Relative Instruction Pointer, explained below) to the function we want to execute.

VirtualAlloc
------------
VirtualAlloc is a function in Windows that can be called. It reserves, commits, or changes the state of a region 
of pages in the virtual address space of the calling process. 
Memory allocated by this function is automatically initialized to zero. 
To allocate memory in the address space of another process, use the VirtualAllocEx function. 
VirtualAlloc is usually used in the C/C++ languages. For example, you can give the following parameters in the VirtualAlloc function:

*lpAddress [in, optional]*: the starting address of the region to allocate.
*dwSize [in]*: the size of the region, in bytes.
*flAllocationType [in]*: the type of memory allocation.
*flProtect [in]*: the memory protection for the region of pages to be allocated.

If the function succeeds, the return value is the base address of the allocated region of pages. 
If the function fails, the return value is NULL.

RIP (Relative Instruction Pointer)
----------------------------------
The instruction pointer, also called the program counter, is a processor register that indicates 
where a computer is in its program sequence. 
Usually this is located in Intel x86 and Itanium microprocessors. 
The instruction pointer is incremented after fetching an instruction, and holds the memory address 
of the next instruction that would be executed.

Read-write memory
-----------------
Read-write memory (RWM) is computer memory that can be both read from and written to. 
This type of memory can be contrasted with read-only memory, which cannot be modified after it is written. 
Having read-write memory design makes devices much more valuable to users, and adds more functionality 
to technologies.
With Read-write memory, you can continually update the data you want. 
Any other kind of memory would not make a lot of sense, as technologies are not often static anymore, 
but are often subject to change.

Setting up XEN/Lib VMI on your computer
=======================================

XEN
---
In this chapter we will explain how we succeeded in setting up XEN on our computer (laptop). 
We installed XEN on Ubuntu, but it is also possible to install XEN on other Linux environments. 
For now, we will explain how we set up XEN 64 bit hypervisor on Ubuntu. 
Before installing, please make sure you have a wired connection. 
Installing XEN over WiFi will lead into more complications.

1) Enter in the command line:: 

	$ sudo apt-get install xen-hypervisor-amd64 
	
   This is the installation command and it will launch the installation of XEN. 
   With Ubuntu 14.04, GRUB will automatically choose to boot Xen first if Xen is installed. 
   GRand Unified Bootloader) is a boot loader package. 
   If you're running a version of Ubuntu before 14.04, you'll have to modify GRUB to default booting to Xen. 
2) Now reboot with the command line:: 
	
	$ sudo reboot
	
3) To verify that XEN was installed correctly, use the command line:: 
	
	$ sudo xl list
	
4) Next up, the installation of bridge-utils with command line:: 

	$ sudo apt-get install bridge-utils

In a bridged setup, it is required that we assign the IP address to the bridged interface. 
Configure network interfaces so that they persist after reboot:

5) Command:: 
	
	$ sudo vi /etc/network/interfaces
	auto lo eth0 xenbr0
	iface lo inet loopback
	iface xenbr0 inet dhcp
 	bridge_ports eth0
	iface eth0 inet manual
	
6) To enable the xenbr0 bridge, we need to restart the network with::

	$ sudo ifdown eth0 && sudo ifup xenbr0 && sudo ifup eth0

The next step is to install a Windows HVM (Hardware Visualized) Guest.  
The main point worth mentioning here is that HVM requires the emulation of ATA, 
Ethernet and other devices, while virtualized CPU and Memory access is performed in hardware to achieve 
good performance. Because of this the default emulated devices are very slow and we generally try 
to use PV (Paravirtualization) drivers within HVM domains. 
We will be installing a set of Windows PV drivers that greatly increase performance once we have our Windows guest running.	

1) First, install the XEN project QEMU (Quick Emulator) package. Do this by putting this in the command line:
	
	# For old Debian versions on the host (up to squeeze)::
  	 
	 aptitude install xen-qemu-dm (= command)
   
	# For newer Debian versions on the host::
  	 
	 aptitude install qemu-system-x86 (= command)
	 
Once the necessary packages are installed we need to create a logical volume to store our 
Windows VM hard disk. In order to do that, create a config file that tells the hypervisor to 
start the domain in HVM mode and boot from the DVD in order to install Windows. 
First, create the new logical volume - name the volume "windows", set the size to 20GB and 
use the volume group vg0 we created earlier. Do this with the following steps:

2) Put in the command line:: 

	lvcreate -nwindows -L20G vg0
	
3) Open a new file “nano windows.cfg” with a text editor of your choice.

4) Paste the config below in the file and save it::

	kernel = "/usr/lib/xen-4.0/boot/hvmloader"
	builder='hvm'
	memory = 4096
	vcpus=4
	name = "ovm-1734"
	vif = ['bridge=xenbr0']
	disk = ['phy:/dev/vg0/windows,hda,w','file:/root/windows.iso,hdc:cdrom,r']
	acpi = 1
	device_model_version = 'qemu-xen-traditional'
	boot="d"
	sdl=0
	serial='pty'
	vnc=1
	vnclisten=""
	vncpasswd=""
	
Important note: it assumes your Windows iso is located in /root/ with the filename windows.iso and 
that you're using squeeze (for wheezy change the kernel line to a xen-4.1 instead of xen-4.0 folder). 
In Debian jessie, please use 'qemu-xen' rather than 'qemu-xen-traditional'.

5) Once Windows is installed by formatting the disk and by following the prompts the domain will restart. 
   Don’t let it boot from the DVD, so destroy the domain with:: 
   
    xm destroy windows
   
6) Change the boot line in the config file to read boot="c"'. Restart the domain with:: 
   
    xm create windows.cfg
   
7) Reconnect to the VNC and the Installation should be finished.

Lib VMI
-------
To monitor the virtual machine that runs XEN, we are using LibVMII. 
LibVMI is a Virtual Machine Introspection which, of course,  can monitor virtual machines running on XEN. 
To install LibVMI you have to take the following steps:

1) First, download the source code from the `Lib VMI Github`_.
   Extract the .zip file in the libvmi folder.
   
2) Then enter the following commands in the command prompt::

	$ ./autogen.sh $ ./configure
	Error: aclocal not found

	$ sudo aptitude install automake autoconf
	Error: Package requirements (glib-2.0 >= 2.16) were not met

	$ sudo aptitude install libglib2.0-dev
	Error: Package requirements (check >= 0.9.4) are not met:

	$ sudo aptitude install check
	
3) After this enter the following command::

	$ make $ sudo ldconfig $ sudo make install
	
When you don’t get any more errors, then you’ll have compiled LibVMI correctly. 
Before any codes can be used, you will have to create a .conf file. 
The libvmi.conf file should look like this::

	ubuntu-hvm
	{
	sysmap = "/boot/System.map-3.13.0-24-generic";
	ostype = "Linux";
	linux_tasks = 0x270;
	linux_name = 0x4a8;
	linux_mm = 0x2a8;
	linux_pid = 0x2e4;
	linux_pgd = 0x40;
	}

“ubuntu-hvm” is the name of the virtual machine that is created.
To verify that everything was installed correctly (especially LibVMI), please put in the command line::

	xen@ubuntu:~/libvmi-0.8$ dpkg --get-selections | grep xen 
	
It should give you exactly this output::

	libc6-xen:i386                install
	libxen-4.1                    install
	libxen-dev                    install
	libxenomai-dev                install
	libxenomai1                   install
	libxenstore3.0                install
	xen-hypervisor-4.1-amd64      install
	xen-tools                     install
	xen-utils-4.1                 install
	xen-utils-common              install
	xenstore-utils                install
	xenwatch                      install

If some libraries are missing, install these libraries by putting in the command line:: 

	$ sudo apt-get install <libraryName>
 
.. _`Lib VMI Github`: https://github.com/libvmi/libvmi

Source list
=======================================
https://nl.wikipedia.org/wiki/Xen

http://wiki.xen.org/wiki/Xen_Project_Software_Overview

http://www.xenproject.org/developers/teams/hypervisor.html

https://en.wikipedia.org/wiki/Sandia_National_Laboratories 

https://github.com/libvmi/libvmi 

http://libvmi.com/ 

https://msdn.microsoft.com/en-us/library/windows/desktop/aa366887(v=vs.85).aspx

https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service 

https://www.techopedia.com/definition/12283/read-write-memory-rwm 

https://en.wikipedia.org/wiki/Program_counter 

**Installation Ubuntu / XEN. One of the manuals we followed (not the WiFi network configuration)**

https://help.ubuntu.com/community/Xen

**Installation Lib VMI**

https://libvmi.wordpress.com/2015/01/23/libvmi-xen-setup/

**The libraries of this URL are needed to verify that LibVMI correctly works**

https://groups.google.com/forum/?fromgroups=#!topic/vmitools/Ql7kU2o3wM8

To install libraries you need to use the command: sudo apt-get install <libraryName>

**Installing Windows VM**

http://wiki.xenproject.org/wiki/Xen_Project_Beginners_Guide#Creating_a_Windows_HVM_.28Hardware_Virtualized.29_Guest 
