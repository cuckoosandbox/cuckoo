In my bachelor thesis I developed a prototype that can be used for comprehensive **static and dynamic Linux malware analysis**. As this prototype is based on the [Cuckoo Sandbox](http://www.cuckoosandbox.org), it is used to automatically run and analyze files inside an isolated Linux operating system and collect several analysis results that outline the malware bevavior. Furthermore, since I adapted and expanded the source code of Cuckoo Sandbox v1.1 the prototype is **capable of running both Linux and Windows malware analysis tasks**.

#### What I've done so far:
* Development of modules that run dynamic analyses:
  * SyscallTracer: Run, control and observe malware
  * FilesystemTracer: Observe filesystem activities using kernel modules
  * ResultLogger: Collect analysis results and directly send them to the host (For this, I adapted the reporting and communication protocols that were already implemented for Windows malware analysis)
* Expansion of existing modules that run static analyses:
  * Implemented static analysis of ELF files
* Several small and not so small changes that needed to be done:
  * Webinterface (the user can choose between linux and windows analysis)
  * Reporting module (formatting and output things)
  * Linux analyzer module (to make my modules run and communicate properly)
  * Created a netlog module (according to cuckoomon) for host-guest result transmission using a linux guest 
  * And even more (this will be updated soon)
* Code update to the latest version of Cuckoo Sandbox (2.0-dev at 2015-09-15)  

#### What needs to be done soon:
* ~~Write a small guide on how to create and setup a linux virtual machine that can be used for analysis tasks
* ~~Update my code to the latest stable version of Cuckoo Sandbox (v1.2)~~ **done!**(2015-09-15)
* ~~Do a pull request to the official Cuckoo Sandbox project


#### Install instructions

#####  Host

Updates and some basic tools
```
sudo apt-get update && sudo apt-get upgrade
sudo apt-get install build-essential git ssh
```

###### Cuckoo dependencies

```
sudo apt-get install python python-pip install mongodb
```

###### Download cuckoo-linux
```
git clone https://github.com/0x71/cuckoo-linux.git
cd cuckoo-linux
```

Install some dependencies first to install the requirements without errors

```
sudo apt-get install python-dev libffi-dev libssl-dev
sudo pip install -r requirements.txt
```

Install yara

```
sudo apt-get install autoconf libtool libjansson-devlibmagic-dev 
cd .. 
wget https://github.com/plusvic/yara/archive/v3.4.0.tar.gz
tar -xzvf v3.4.0.tar.gz
cd yara-3.4.0/
./bootstrap.sh
./configure --enable-cuckoo --enable-magic
make
sudo make install
```

Install ssdeep/pydeep

```
wget http://ssdeep.sourceforge.net/#download
# extract archive
cd ssdeep-2.13/
autoreconf
# if an error is display, run 
automake --add-missing
./configure
make
sudo make install
sudo pip install pydeep
```

Install Virtualbox

```
wget http://download.virtualbox.org/virtualbox/5.0.8/virtualbox-5.0_5.0.8-103449~Ubuntu~trusty_amd64.deb
sudo dpkg -i virtualbox-5.0_5.0.8-103449~Ubuntu~trusty_amd64.deb
# Solve dependency errors using 'sudo apt-get install --fix-missing -f'
```

Install tcpdump
```
sudo apt-get install tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
```

Install MySQL
```
sudo apt-get install mysql-client mysql-server libmysqlclient-dev
sudo pip install mysql-python
```

MySQL Setup
```
mysql -u root -p
create database cuckoo;
create user cuckoo@localhost;
set password for cuckoo@localhost = password('**********');
grant all on cuckoo.* to cuckoo@localhost;
```

##### Guest
* Enable guest virtualization on host
* Install guest virtual machine

```
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install build-essential ssh -y
sudo apt-get install python2.7-dev python-setuptools python-pip -y
sudo apt-get install libyaml-dev
sudo easy_install watchdog python-ptrace
sudo apt-get install python-bson

sudo apt-get install lib32z1 lib32ncurses5 lib32bz2-1.0
```

copy cuckoo-linux/agent/agent.py to guest and run it as root

done!
