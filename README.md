![Cuckoo](http://cuckoosandbox.org/graphic/cuckoo.png)

[Cuckoo Sandbox](http://www.cuckoosandbox.org) is the leading open source
automated malware analysis system.

What does that mean? It simply means that you can throw any suspicious file at
it and in a matter of seconds Cuckoo will provide you back some detailed
results outlining what such file did when executed inside an isolated
environment.

If you want to contribute to development, please read
[this](http://www.cuckoosandbox.org/development.html) and
[this](http://www.cuckoofoundation.org/contribute.html) first. Make sure you
check our Issues and Pull Requests and that you join our IRC channel.

<hr />

This branch represents the new **cuckoo package**. Its setup instructions may
be found [in](https://cuckoo.sh/docs/installation/host/requirements.html)
[our](https://cuckoo.sh/docs/development/package.html)
[documentation](https://cuckoo.sh/docs/index.html).

We also feature a
[legacy](https://github.com/cuckoosandbox/cuckoo/tree/legacy) branch where
the code is laid out as you have known for the last years up until the
**2.0.0** release. In the foreseeable future we'll allow our users to do pull
requests against the legacy branch and in return we'll help out with merging
to the new master branch. In other words, if you care to see your custom
functionality still present after upgrading to the latest version of Cuckoo,
we suggest to start on those pull requests.

This is a development version, we do not recommend its use in production.

You can find a full documentation of the latest stable release
[here](http://docs.cuckoosandbox.org).

<hr />

[![Linux Build Status](https://travis-ci.org/cuckoosandbox/cuckoo.png?branch=package)](https://travis-ci.org/cuckoosandbox/cuckoo)
[![Windows Build status](https://ci.appveyor.com/api/projects/status/p892esebjdbhq653/branch/package?svg=true)](https://ci.appveyor.com/project/jbremer/cuckoo/branch/package)
[![Coverage Status](https://coveralls.io/repos/github/cuckoosandbox/cuckoo/badge.svg?branch=package)](https://coveralls.io/github/cuckoosandbox/cuckoo?branch=package)
[![codecov](https://codecov.io/gh/cuckoosandbox/cuckoo/branch/master/graph/badge.svg)](https://codecov.io/gh/cuckoosandbox/cuckoo)
