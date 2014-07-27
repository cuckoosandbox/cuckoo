from ctypes import *
import time 
import socket
import _winreg

# resolv hostnames
hostnames = ["google.com","twitter.com","reddit.com"]
for h in hostnames:
	addr = socket.gethostbyname(h)


# load some librarires
kernel32 = windll.kernel32 
msvcrt =  cdll.msvcrt 

# edit registry 
key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, "Software\\Cuckoo\\ReleaseTest", 1, _winreg.KEY_ALL_ACCESS)

time.sleep(3)
