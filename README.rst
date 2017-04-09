.. image:: http://cuckoosandbox.org/graphic/cuckoo.png
   :alt: Cuckoo Sandbox
   :target: https://cuckoosandbox.org/

`Cuckoo Sandbox <https://cuckoosandbox.org/>`_ is the leading open source
automated malware analysis system.

What does that mean? It simply means that you can throw any suspicious file at
it and in a matter of seconds Cuckoo will provide you back some detailed
results outlining what such file did when executed inside an isolated
environment.

If you want to contribute to development, please read the
`development guidelines`_ and the `contribution requirements`_ first. Make
sure you check our Issues and Pull Requests and that you join our IRC channel.

This branch represents the new **cuckoo package**. Its setup instructions may
be found `in <https://cuckoo.sh/docs/installation/host/requirements.html>`_
`our <https://cuckoo.sh/docs/development/package.html>`_
`documentation <https://cuckoo.sh/docs/index.html>`_.

We also feature a
`legacy <https://github.com/cuckoosandbox/cuckoo/tree/legacy>`_ branch where
the code is laid out as you have known for the last years up until the
**2.0.0** release. In the foreseeable future we'll allow our users to do pull
requests against the legacy branch and in return we'll help out with merging
to the new master branch. In other words, if you care to see your custom
functionality still present after upgrading to the latest version of Cuckoo,
we suggest to start on those pull requests.

This is a development version, we do not recommend its use in production.

You can find a full documentation of the latest stable release
`here <http://docs.cuckoosandbox.org/>`_.

.. image:: https://travis-ci.org/cuckoosandbox/cuckoo.png?branch=package
   :alt: Linux Build Status
   :target: https://travis-ci.org/cuckoosandbox/cuckoo

.. image:: https://ci.appveyor.com/api/projects/status/p892esebjdbhq653/branch/package?svg=true
   :alt: Windows Build Status
   :target: https://ci.appveyor.com/project/jbremer/cuckoo/branch/package

.. image:: https://coveralls.io/repos/github/cuckoosandbox/cuckoo/badge.svg?branch=package
   :alt: Coverage Coverage Status
   :target: https://coveralls.io/github/cuckoosandbox/cuckoo?branch=package

.. image:: https://codecov.io/gh/cuckoosandbox/cuckoo/branch/master/graph/badge.svg
   :alt: Codecov Coverage Status
   :target: https://codecov.io/gh/cuckoosandbox/cuckoo

.. _`development guidelines`: http://www.cuckoosandbox.org/development.html
.. _`contribution requirements`: http://www.cuckoofoundation.org/contribute.html
