====================
Installing the Agent
====================

From release 0.4 Cuckoo adopts a custom agent that runs inside the Guest and
that handles the communication and the exchange of data with the Host.
This agent is designed to be cross-platform, therefore you should be able
to use it on Windows, Android, Linux, and Mac OS X.
In order to make Cuckoo work properly, you'll have to install and start this
agent.

It's quite simple.

In the ``$CWD/agent/`` directory you will find the ``agent.py`` file. Copy
this file to the Guest operating system (in whatever way you want, perhaps a
temporary shared folder or by downloading it from a webserver on the host, we
recommend the latter) and run it. The Agent will launch a small API server
that the host will be able to talk to.

On Windows simply launching the script will also spawn a Python window, if
you want to hide it you can rename the file from ``agent.py`` to **agent.pyw**
which will prevent the console window from spawning.

If you want the script to be launched at Windows' boot, just place the file in
the `Startup` folder.
