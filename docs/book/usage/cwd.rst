==============================
Cuckoo Working Directory Usage
==============================

.. note:: Before reading this page, please read on installing Cuckoo and
    the :doc:`../installation/host/cwd`.

Before we go into the subject of using the ``CWD`` we're first going to walk
you through the many improvements on your Quality of Life during your daily
usage of Cuckoo Sandbox with the introduction of the ``Cuckoo Package`` and
``CWD`` and some of the new features that come along with this.

So simply put, the ``CWD`` is a per-Cuckoo instance configuration directory.
While people generally speaking only run one Cuckoo instance per server, this
still yields a lot of maintenance-related improvements:

* As outlined by :doc:`../installation/host/installation` installing Cuckoo
  and updating it will now be pretty much ``pip install -U cuckoo``.
* Due to Cuckoo now being an official Python Package we have a much tighter
  control on how its installed on users' systems. No longer will users have
  incorrect versions of third party libraries installed breaking their setup.
* Because updating is much easier (again, ``pip install -U cuckoo``) we will
  be able to **put out new versions more often**. E.g., when one or more users
  run into a bug, we'll be able to put out a fix quickly - this has happened a
  few times in the past in a way that we weren't able to properly mitigate
  such issues (leaving users high & dry for months).
* **The Cuckoo Configuration is no longer part of the Git repository**. Users
  who have updated Cuckoo in the past will have seen the effort involved in
  making a backup of their configuration, pulling a new version of Cuckoo, and
  either restoring their old configuration or applying the configuration
  against the new Cuckoo version by hand.
* With the new ``CWD`` all configurable files will be in one centralized
  place in logically structured subdirectories.
* Given that a ``CWD`` denotes *one* Cuckoo instance, it is possible to have
  multiple Cuckoo instances through multiple ``CWD``'s while having
  installed/deployed Cuckoo only once.
* With the addition of the ``cuckoo`` executable and its associated
  :ref:`cuckoo_apps` (subcommands) **the various Cuckoo commands are now
  centralized into one command**.

Usage
=====

After having installed the ``Cuckoo Package`` (:ref:`installing`) and setup
the initial ``Cuckoo Working Directory`` (:doc:`../installation/host/cwd`) it
is time to actually get started with Cuckoo. Just to reiterate, installing the
latest version of Cuckoo in a ``virtualenv`` environment may look roughly as
follows (note the ``pip install -U pip setuptools``, for more information see
also :ref:`pip_install_issue`).

.. code-block:: bash

    $ virtualenv venv
    $ . venv/bin/activate
    (venv)$ pip install -U pip setuptools
    (venv)$ pip install -U cuckoo
    (venv)$ cuckoo --cwd ~/.cuckoo

First of all you'll probably want to update the default Cuckoo configuration
in the ``$CWD/conf/`` directory. If just to switch from the default SQLite3
database to, e.g., PostgreSQL, or to register some virtual machines (more
information on setting up Virtual Machines can be found in
:doc:`../installation/guest/index`). Note that in order to view the results of
analyses in the Web Interface later on it is necessary to enable the
``mongodb`` reporting module in ``$CWD/conf/reporting.conf`` (see also
:doc:`web`).

We then proceed by downloading the Cuckoo Community which includes over 300
Cuckoo Signatures which summarize a wide array of malicious behavior in a
digestible way, simplifying the final results of an analysis. Downloading the
Cuckoo Community into our ``CWD`` may be done as follows::

    (venv)$ cuckoo community

Alternatively, if you have a local copy of the community ``.tar.gz`` file
(e.g., after running
``wget https://github.com/cuckoosandbox/community/archive/master.tar.gz``)
this can be imported as follows::

    (venv)$ cuckoo community --file master.tar.gz

Now we're good to go let's submit some samples and URLs using the command-line
:ref:`submitpy`. Note that multiple tasks may be submitted at once::

    (venv)$ cuckoo submit /tmp/sample1.exe /tmp/sample2.exe /tmp/sample3.exe
    Success: File "/tmp/sample1.exe" added as task with ID #1
    Success: File "/tmp/sample2.exe" added as task with ID #2
    Success: File "/tmp/sample3.exe" added as task with ID #3
    (venv)$ cuckoo submit --url google.com bing.com
    Success: URL "google.com" added as task with ID #4
    Success: URL "bing.com" added as task with ID #5

For the actual analysis of these samples, one will have to run the Cuckoo
daemon. Which is equally straightforward. Do keep in mind that, by default,
the command will run indefinitely (unless a ``maximum analysis count`` was
provided through the ``-m`` parameter, e.g., ``-m 5``).

.. code-block:: bash

    # This command is equal to what used to be "./cuckoo.py -d".
    (venv)$ cuckoo -d

Now in order to inspect the analyses that have run we start the Web Interface.
For small and/or home setups this may be done using the built-in Django web
server as follows, although we recommend a proper :ref:`web_deployment` for
any bigger setup.

.. code-block:: bash

    (venv)$ cuckoo web
    Performing system checks...

    System check identified no issues (0 silenced).
    March 31, 2017 - 12:10:46
    Django version 1.8.4, using settings 'cuckoo.web.web.settings'
    Starting development server at http://localhost:8000/
    Quit the server with CONTROL-C.

There are some additional ``Cuckoo Apps`` such as ``cuckoo clean``
(:ref:`cuckoo-clean`), the :ref:`rooter`, and various other utilities listed
in :ref:`cuckoo_apps`, but other than that there's not much more to learn
about installing and running Cuckoo Sandbox - so, happy analyzing.
