==================
Physical Sandboxes
==================

The physical machine manager provides Cuckoo with the ability to
communicate with, and run samples on physical sandboxes.  This capability
provides the ability to analyze malware that is capable of detecting whether
or not it is being run in a virtualized environment.

Requirements
============

The physical machine manager uses RPC requests to reboot physical machines.
  The `net` command is required for this to be accomplished, and is available
  from the samba-common-bin package.  

On Debian/Ubuntu:
    $ sudo apt-get install samba-common-bin

In order for the physical machine manager to work, you must have a way
for physical machines to be returned to a clean state.  In development/testing
Fog (http://www.fogproject.org/) was used as a platform to handle re-imaging
the physical machines.  However, any re-imaging platform can be used
(Clonezilla, Deepfreeze, etc) to accomplish this.


Setup using Fog
===============
The Fog User Guide (http://www.fogproject.org/wiki/index.php/FOGUserGuide) is 
an excellent resource for setting up a Fog server to handle imaging computers.
Upon setting up Fog, the general procedure for using physical machines as 
sandboxes is as follows:
        1.  Install OS onto computer
        2.  Install additional applications (Microsoft Office, Adobe Reader, Java, etc.)
        3.  Prepare the physical machine to run samples (see below)
        4.  Create new Image task in Fog
        5.  Reboot computer, upload image to Fog server
        6.  Configure Fog server to schedule a deployment of images (cron-style)
        7.  Edit cuckoo configuration file to include new physical machines
        8.  Run samples 

Preparing The Guest (Physical Machine)
======================================

Using a physical machine manager requires a few more configuration options than
the virtual machine managers in order to run properly.  In addition to the steps
laid out in the regular Preparing the Guest section, some settings need to be changed
for physical machines to work properly.  
    - Enable auto-logon
    - Enable Remote RPC
    - Turn off paging (Optional)
    - Disable Screen Saver (Optional)

In Windows 7 the following commands can be entered into an Administrative command prompt to enable auto-logon and Remote RPC.  

    reg add "hklm\\software\\Microsoft\\Windows NT\\CurrentVersion\\WinLogon" /v DefaultUserName /d <USERNAME> /t REG_SZ /f
    
    reg add "hklm\\software\\Microsoft\\Windows NT\\CurrentVersion\\WinLogon" /v DefaultPassword /d <PASSWORD> /t REG_SZ /f
    
    reg add "hklm\\software\\Microsoft\\Windows NT\\CurrentVersion\\WinLogon" /v AutoAdminLogon /d 1 /t REG_SZ /f
    
    reg add "hklm\\system\\CurrentControlSet\\Control\\TerminalServer" /v AllowRemoteRPC /d 0x01 /t REG_DWORD /f
    
    reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v LocalAccountTokenFilterPolicy     /d 0x01 /t REG_DWORD /f
 


Setup using VMWare (Bonus!)
===========================

Traditionally cuckoo requires the cuckoo server to be running some sort of virtualization software (e.g. VMware, Virtualbox, etc).  This machine manager will also work with other virtual machines, so long as they are configured to revert to a snapshot on shutdown/reboot, and running the agent.py script.  A use case for this functionality would be to run the cuckoo server and the guest sandboxes each in their own VM on a single host, allowing for development/testing of cuckoo without requiring a dedicated Linux host for cuckoo.
