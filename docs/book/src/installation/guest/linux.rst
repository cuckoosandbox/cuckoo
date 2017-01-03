==========================
Installing the Linux guest
==========================

Add agent to autorun, the easier way is to add it to crontab::

    sudo crontab -e
    @reboot python path_to_agent.py

Install dependencies::

    sudo apt-get install systemtap gcc linux-headers-$(uname -r) 

Compile Kernel extension::

    wget https://raw.githubusercontent.com/cuckoosandbox/cuckoo/master/data/strace.stp
    sudo stap -r $(uname -r) strace.stp -m stap_ -v

When you will start see **Pass 5: starting run.** Press ctrl+c to stop it You should see stap_.ko in the same folder

Test Kernel extension::

    staprun -v ./stap_.ko

Output should be something like **staprun:insert_module:x Module stap_ inserted from file path_to_stap_.ko**
stap_.ko should be placed in /root/.cuckoo::

    mkdir /root/.cuckoo
    mv stap_.ko /root/.cuckoo/


Disable firewall::
    
    sudo ufw disble
