.. image:: https://cuckoosandbox.org/assets/images/cuckoo-black.png
   :alt: Cuckoo Sandbox
   :target: https://cuckoosandbox.org/

**PLEASE NOTE: Cuckoo Sandbox 2.x is currently unmaintained. Any open issues
or pull requests will most likely not be processed, as a current full rewrite
of Cuckoo is undergoing and will be announced soon.**

`Cuckoo Sandbox <https://cuckoosandbox.org/>`_ is the leading open source
automated malware analysis system.

What does that mean? It simply means that you can throw any suspicious file at
it and in a matter of seconds Cuckoo will provide you back some detailed
results outlining what such file did when executed inside an isolated
environment.

If you want to contribute to development, report a bug, make a feature request
or ask a question, please first take a look at our `community guidelines`_.
Make sure you check our existing Issues and Pull Requests and that you join
our `IRC or Slack channel <https://cuckoosandbox.org/discussion>`_.

For setup instructions, please refer
`to <https://docs.cuckoosandbox.org/en/latest/installation/host/requirements>`_
`our <https://docs.cuckoosandbox.org/en/latest/installation/host/installation>`_
`documentation <https://docs.cuckoosandbox.org/en/latest/>`_.

This is a development version, and we do not recommend its use in production; the
latest stable version may be installed through :code:`pip install -U cuckoo`.

You can find the full documentation of the latest stable release
`here <https://docs.cuckoosandbox.org/en/latest/>`_.

.. image:: https://travis-ci.org/cuckoosandbox/cuckoo.png?branch=master
   :alt: Linux Build Status
   :target: https://travis-ci.org/cuckoosandbox/cuckoo

.. image:: https://ci.appveyor.com/api/projects/status/p892esebjdbhq653/branch/master?svg=true
   :alt: Windows Build Status
   :target: https://ci.appveyor.com/project/jbremer/cuckoo/branch/master

.. image:: https://coveralls.io/repos/github/cuckoosandbox/cuckoo/badge.svg?branch=master
   :alt: Coverage Coverage Status
   :target: https://coveralls.io/github/cuckoosandbox/cuckoo?branch=master

.. image:: https://codecov.io/gh/cuckoosandbox/cuckoo/branch/master/graph/badge.svg
   :alt: Codecov Coverage Status
   :target: https://codecov.io/gh/cuckoosandbox/cuckoo

.. _`community guidelines`: https://docs.cuckoosandbox.org/en/latest/introduction/community.html
.. _`contribution requirements`: http://www.cuckoofoundation.org/contribute.html
