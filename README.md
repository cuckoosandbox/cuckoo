# Cuckoo Sandbox Fork

This fork is for analyzing files with Cuckoo primarily on Ubuntu18.04 guests with Virtualbox5.2.
Tested on Ubuntu 20.04.

## Improvements of original cuckoo
This cuckoo forks main purpose is to allow the analysis of programms in docker-conatiners. It modifies the systemtap script and includes all programms running in containers into the analysis. It also writes down which Systemcall comes from which container (logs the id). Writing the container id into the log poptentially breaks other cuckoo features/analysis. The log with all syscalls is found in ~/.cuckoo/storage/analyses/X/logs/all.stap . Instead of the result.json created by cuckoo this forks creates an output in the STIX 2.0 format. The analysis result can be found in ~/.cuckoo/storage/analyses/X/stix-file.json . The file contains information about files written, processes created and network connections made.

## Difference in setup
The setup on differs slightly from the original setup.
On the host you have to install cuckoo with:
```shell
pip install -e https://github.com/axel1200/cuckoo.git

```
instead of:
```shell
pip install cuckoo
```
On the guest install the systemtab script with:
```shell
wget https://raw.githubusercontent.com/axel1200/cuckoo/master/stuff/systemtap/strace.stp
stap -p4 -r $(uname -r) strace.stp -m stap_ -v -g
```
Notice that you just download the script from a different location and that you have to add the `-g` flag.

### Some notes on setup
Host:
```shell
  sudo apt install python2 virtualenv -y
  virtualenv cuckoo-venv -p python2.7
  source cuckoo-venv/bin/activate
  sudo apt install curl tcpdump python-dev libffi-dev libssl-dev libjpeg-dev zlib1g-dev swig libcurl4 -y
  curl https://bootstrap.pypa.io/get-pip.py --output get-pip.py
  python2 get-pip.py
  wget http://archive.ubuntu.com/ubuntu/pool/main/libv/libvpx/libvpx5_1.7.0-3_amd64.deb
  sudo dpkg -i libvpx5_1.7.0-3_amd64.deb
  wget https://download.virtualbox.org/virtualbox/5.2.40/virtualbox-5.2_5.2.40-137108~Ubuntu~bionic_amd64.deb
  sudo apt install ./virtualbox-5.2_5.2.40-137108~Ubuntu~bionic_amd64.deb -y
  sudo adduser cuckoo
  sudo usermod -a -G vboxusers cuckoo
  sudo groupadd pcap
  sudo usermod -a -G pcap cuckoo
  sudo chgrp pcap /usr/sbin/tcpdump
  sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
  git clone https://github.com/axel1200/cuckoo
  cd cuckoo
  python setupy.py sdist
  pip install .
  cuckoo -d
  mv new_config_files/reporting.conf $CWD/conf/reporting.conf
```
If the machine shall be able to communicate with the internet, execute the following commands on host.
Replace eth0 with the network interface of your machine.
```shell
  sudo iptables -t nat -A POSTROUTING -o eth0 -s 192.168.56.0/24 -j MASQUERADE
  sudo iptables -P FORWARD DROP
  sudo iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
  sudo iptables -A FORWARD -s 192.168.56.0/24 -j ACCEPT
  sudo iptables -A FORWARD -s 192.168.56.0/24 -d 192.168.56.0/24 -j ACCEPT
  sudo iptables -A FORWARD -j LOG
  echo 1 | sudo tee -a /proc/sys/net/ipv4/ip_forward
  sudo sysctl -w net.ipv4.ip_forward=1
```

Compile the new SystemTap script on your guest system:
```shell
  wget https://raw.githubusercontent.com/axel1200/cuckoo/master/stuff/systemtap/strace.stp
  sudo stap -p4 -r $(uname -r) strace.stp -m stap_ -v -g
```
