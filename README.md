# cuckoo-osx-analyzer
[![Build Status](https://travis-ci.org/rodionovd/cuckoo-osx-analyzer.svg?branch=master)](https://travis-ci.org/rodionovd/cuckoo-osx-analyzer) [![GitHub version](https://badge.fury.io/gh/rodionovd%2Fcuckoo-osx-analyzer.svg)](http://badge.fury.io/gh/rodionovd%2Fcuckoo-osx-analyzer) [![Code Climate](https://codeclimate.com/github/rodionovd/cuckoo-osx-analyzer/badges/gpa.svg)](https://codeclimate.com/github/rodionovd/cuckoo-osx-analyzer)
My [GSoC project](http://www.google-melange.com/gsoc/project/details/google/gsoc2015/rodionovd/5649050225344512) aiming at building an OS X analyzer for [Cuckoo Sandbox](http://www.cuckoosandbox.org/) project.  

:warning: **WIP** :warning:  
----

### Usage

> See also: [`bootstrap_host.sh`](./scripts/bootstrap_host.sh) and [`bootstrap_guest.sh`](./scripts/bootstrap_guest.sh)

##### Guest machine setup

 0. Install `pt_deny_attach` kernel extension suggested by @phretor. That's an optional step, see [this comment](https://github.com/rodionovd/cuckoo-osx-analyzer/issues/6#issuecomment-101322097) for more details.

 1. Since this analyser uses some utilities that require additional privileges to run, you may want to enable passwordless `sudo` for them. This may be accomplished by modifying `/etc/sudoers` file:  

  ```diff
--- a/etc/sudoers
+++ b/etc/sudoers
@@ -43,3 +43,5 @@ root  ALL=(ALL) ALL
 # Samples
 # %users  ALL=/sbin/mount /cdrom,/sbin/umount /cdrom
 # %users  localhost=/sbin/shutdown -h now
+
+ username   ALL=(root) NOPASSWD: /usr/sbin/dtrace
+ username   ALL=(root) NOPASSWD: /bin/date
  ```
  (replace `username` above with an actual user name).  

 2. Set the network settings: IP address, subnet mask, router address and DNS servers:  
  ```bash
  $ sudo networksetup -setmanual Ethernet 192.168.56.101 255.255.255.0 192.168.56.1
  $ sudo networksetup -setdnsservers Ethernet 8.8.8.8 8.8.4.4
  ```

 > Also, if you're using VirtualBox: don't forget to setup your host-only internet adapter and attach it to the guest machine.

 3. Download and launch Cuckoo's `agent.py`:  

  ```bash
$ curl -o /Users/Shared/agent.py https://raw.githubusercontent.com/cuckoobox/cuckoo/master/agent/agent.py
$ python /Users/Shared/agent.py
  ```

 4. Take a VM snapshot. It's <kbd>cmd+T</kbd> for VirtualBox.

##### On the host side (OS X)

 0. Setup internet traffic forwarding to and from your guest machine. Here's an example of using `pfctl` to forward traffic to and from `vboxnet0` interface:

  ```shell
  $ sudo sysctl -w net.inet.ip.forwarding=1

  $ rules="nat on en1 from vboxnet0:network to any -> (en1)
  pass inet proto icmp all
  pass in on vboxnet0 proto udp from any to any port domain keep state
  pass quick on en1 proto udp from any to any port domain keep state"

  $ echo "$rules" > ./pfrules
  $ sudo pfctl -e -f ./pfrules
  $ rm -f ./pfrules
  ```

  > **Note that you'll have to re-enable traffic forwarding every time you reboot the host machine.**  

 1. Clone this repository:  

  ```shell
$ git clone https://github.com/rodionovd/cuckoo-osx-analyzer.git ~/cuckoo-osx-analyzer
# Or (if you prefer SSH):
# $ git clone git@github.com:rodionovd/cuckoo-osx-analyzer.git cuckoo-osx-analyzer
  ```

 2. Symlink `analyzer/darwin` directory from this repository to your own copy of [Cuckoo Sandbox](https://github.com/cuckoobox/cuckoo/):

  ```shell
$ cd /path/to/cuckoo/sandbox/
$ cd ./analyzer
$ ln -s ~/cuckoo-osx-analyzer/analyzer/darwin darwin

  ```

 3. Submit an analysis job:

  ```bash
$ ./utils/submit.py --platform darwin ~/bin/sample
  ```

### Adding custom API signatures
You can add custom API signatures and define data types in [`signatures.json`](./cuckoo-osx-analyzer/analyzer/darwin/lib/core/data/signatures.yml) and [`types.yml`](./cuckoo-osx-analyzer/analyzer/darwin/lib/core/data/types.yml) files.

### Tests

You can run the test suite with `nose`:  

```bash
$ cd ./cuckoo-osx-analyzer
$ sudo -H pip install -r requirements.txt
$ nosetests
```

> NOTE: Running [Cuckoo integration tests](https://github.com/rodionovd/cuckoo-osx-analyzer/blob/master/tests/test_cuckoo.py) requires Cuckoo to be installed in the same directory as the analyzer itself:
> ```
$ ls
cuckoo cuckoo-osx-analyzer
```

See also: [`.travis.yml`](https://github.com/rodionovd/cuckoo-osx-analyzer/blob/master/.travis.yml) and [Travis CI project](https://travis-ci.org/rodionovd/cuckoo-osx-analyzer).


### Roadmap, issues and reports  

See my [weekly reports](https://github.com/rodionovd/cuckoo-osx-analyzer/wiki/GSoC-weekly-reports) and [Issues](https://github.com/rodionovd/cuckoo-osx-analyzer/issues).


-----

Dmitry Rodionov, i.am.rodionovd@gmail.com  
2015
