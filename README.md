# cuckoo-osx-analyzer
My [GSoC project](http://www.google-melange.com/gsoc/project/details/google/gsoc2015/rodionovd/5649050225344512) aiming at building an OS X analyzer for [Cuckoo Sandbox](http://www.cuckoosandbox.org/) project.  

:warning: **WIP** :warning:  
----

### Usage


##### Guest machine setup

 1. Currently, this analyser uses `dtrace`, so the guest OS user must be able to launch this utility without a password prompt. This may be accomplished by modifying `/etc/sudoers` file:  

```diff
--- a/etc/sudoers
+++ b/etc/sudoers
@@ -43,3 +43,5 @@ root  ALL=(ALL) ALL
 # Samples
 # %users  ALL=/sbin/mount /cdrom,/sbin/umount /cdrom
 # %users  localhost=/sbin/shutdown -h now
+
+ username   ALL=(root) NOPASSWD: /usr/sbin/dtrace
+ username   ALL=(root) NOPASSWD: /usr/bin/dtruss
```
(replace `username` above with an actual name of the user).

 2. Download and launch Cuckoo's `agent.py`:  

```bash
$ curl -o /Users/Shared/agent.py https://raw.githubusercontent.com/cuckoobox/cuckoo/master/agent/agent.py
$ python /Users/Shared/agent.py
```

 3. Take a VM snapshot. It's `cmd+T` for VirtualBox.

##### On the host side


 1. Clone this repository:  

```shell
$ git clone https://github.com/rodionovd/cuckoo-osx-analyzer.git ~/cuckoo-osx-analyzer
# Or (if you prefer SSH):
# $ git clone git@github.com:rodionovd/cuckoo-osx-analyzer.git cuckoo-osx-analyzer
```

 2. Symlink `analyzer/darwin` directory from this repository to your [Cuckoo Sandbox](https://github.com/cuckoobox/cuckoo/) copy:

```shell
$ cd /path/to/cuckoo/sandbox/
$ cd ./analyzer
$ ln -s ~/cuckoo-osx-analyzer/analyzer/darwin darwin

```

 3. Submit an analysis job:

```bash
$ /utils/submit.py --platform darwin ~/bin/sample
```

### Roadmap, bugs and whatnot  

Please, look into the Issues and PRs of this repo.

### Tests

You can run the test suite with `nose`:  

```bash
$ cd ./cuckoo-osx-analyzer
$ # [sudo] pip install nose
$ nosetests
```

-----

Dmitry Rodionov, i.am.rodionovd@gmail.com  
2015
