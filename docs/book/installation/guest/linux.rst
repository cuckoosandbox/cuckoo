==========================
Installing the Linux guest
==========================

Add agent to autorun, the easier way is to add it to crontab::

    sudo crontab -e
    @reboot python path_to_agent.py

The following instructions are only for x32/x64 linux guests
============================================================

Install dependencies::

    sudo apt-get install systemtap gcc linux-headers-$(uname -r)

Compile Kernel extension::

    wget https://raw.githubusercontent.com/cuckoosandbox/cuckoo/master/data/strace.stp
    sudo stap -p4 -r $(uname -r) strace.stp -m stap_ -v

Once the compilation finishes you should see the file ``stap_.ko`` in the same
folder. You will now be able to test the STAP kernel extension as follows::

    $ staprun -v ./stap_.ko
    staprun:insert_module:x Module stap_ inserted from file path_to_stap_.ko

In order to setup the Guest, you will have to place ``stap_.ko`` in
``/root/.cuckoo``::

    mkdir /root/.cuckoo
    mv stap_.ko /root/.cuckoo/

And finally you'll want to disable the firewall::

    $ sudo ufw disable
