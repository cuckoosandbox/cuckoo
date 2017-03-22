===================================
Development with the Python Package
===================================

With the new Python package developing and testing code now works slightly
different than it used to be. As one will first have to :ref:`install_cuckoo`
before being able to use it in the first place, a simple modify-and-test
development sequence doesn't work out-of-the-box as it used to do.

Following we outline how to develop and test new features while using the
Cuckoo Package.

* Initialize a new ``virtualenv``.

  .. code-block:: bash

      $ virtualenv /tmp/cuckoo-development
      $ . /tmp/cuckoo-development/bin/activate

* In order to create a Cuckoo distribution package it is required to obtain
  the matching monitoring binaries from our `Community repository`_ for this
  version of Cuckoo. Fortunately we provide a simple-to-use script to fetch
  them semi-automatically for you. From the repository root directory one may
  run as follows to automatically grab the binaries.

  .. code-block:: bash

      (cuckoo-development)$ python stuff/monitor.py

* Install Cuckoo in ``development`` mode, in which files from the current
  directory (a ``git clone``'d Cuckoo repository on the ``package`` branch)
  will be used during execution.

  .. code-block:: bash

      (cuckoo-development)$ python setup.py develop

You will now be ready to modify and test files. Note that the code files are
located in the `cuckoo/ directory`_ of the Git repository and the fact that,
even though you will be testing a ``development`` version of the repository,
all the *rules* from the :doc:`../installation/host/cwd` and
:doc:`../usage/cwd` are still in-place.

Happy development! Please reach out to us if you require additional help to
get up-and-running with the latest development tricks.

.. _`cuckoo/ directory`: https://github.com/cuckoosandbox/cuckoo/tree/package/cuckoo
.. _`Community repository`: https://github.com/cuckoosandbox/community
