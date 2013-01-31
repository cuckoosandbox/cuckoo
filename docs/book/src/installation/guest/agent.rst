=================
Install the Agent
=================

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

To add the agent to run on startup on Windows:
- copy it to your python installation directory
- Press Start -> Run -> regedit.exe
- Navigate to the key
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
- Right click and create a new "String Value" and name it "Agent"
- Double click on your new entry and set the value as the location of the
cuckoo agent "C:\Python27\agent.pyw"
- If done correctly you should be able to see your entry in msconfig.exe
