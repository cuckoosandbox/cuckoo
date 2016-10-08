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

* If you need to be able to actually analyze tasks with this development
  setup, then you'll have to create the following directory in the repository
  ``cuckoo/data/monitor/cf3b0957e39242885f7e5a7d6f49245b3a88a2fd`` containing
  the files that may be found `in the Cuckoo community`_. If you don't need to
  do any analyses and merely would like to work on reprocessing tasks (i.e.,
  ``cuckoo process -r 1234``) or on the Cuckoo Web Interface, then you may set
  the ``ONLYINSTALL=1`` environment variable before the next step.

* Install Cuckoo in ``development`` mode, in which files from the current
  directory (a ``git clone``'d Cuckoo repository on the ``package`` branch)
  will be used during execution.

  .. code-block:: bash

      (cuckoo-development)$ python setup.py develop

  Or in case you'd like to skip the Cuckoo Monitor binaries, install Cuckoo as
  follows.

  .. code-block:: bash

      (cuckoo-development)$ ONLYINSTALL=1 python setup.py develop

You will now be ready to modify and test files. Note that the code files are
located in the `cuckoo/ directory`_ of the Git repository and the fact that,
even though you will be testing a ``development`` version of the repository,
all the *rules* from the :doc:`../installation/host/cwd` and
:doc:`../usage/cwd` are still in-place.

Happy development! Please reach out to us if you require additional help to
get up-and-running with the latest development tricks.

.. _`cuckoo/ directory`: https://github.com/cuckoosandbox/cuckoo/tree/package/cuckoo
.. _`in the Cuckoo community`: https://github.com/cuckoosandbox/community/tree/master/data/monitor/cf3b0957e39242885f7e5a7d6f49245b3a88a2fd
