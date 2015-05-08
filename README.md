# cuckoo-osx-analyzer
My [GSoC project](http://www.google-melange.com/gsoc/project/details/google/gsoc2015/rodionovd/5649050225344512) aiming at building an OS X analyzer for [Cuckoo Sandbox](http://www.cuckoosandbox.org/) project.  

:warning: **WIP** :warning:  
----

### Usage

Just move/copy/symlink the `analyzer/darwin` directory from this repository into your [Cuckoo Sandbox](https://github.com/cuckoobox/cuckoo/) copy. Then you can start submit your OS X jobs:  

```bash
$ /utils/submit.py --platform darwin ~/bin/sample
```

### Roadmap, bugs and whatnot  

Please, look into the Issues and PRs of this repo.

### Tests

You can run the test suite either by using `nose`:  

```bash
$ cd ./cuckoo-osx-analyzer
$ # [sudo] pip install nose
$ nosetests
```

or by calling tests directly:  

```bash
$ cd ./cuckoo-osx-analyzer
$ python tests/foo_tests.py # maybe even tests/*.py
```

-----

Dmitry Rodionov, i.am.rodionovd@gmail.com  
2015