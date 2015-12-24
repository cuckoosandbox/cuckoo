=================
Development Notes
=================

Git branches
============

Cuckoo Sandbox source code is available in our `official git repository`_.

.. _`official git repository`: https://github.com/cuckoosandbox/cuckoo

Up until version 1.0 we used to coordinate all ongoing development in a
dedicated "development" branch and we've been exclusively merging pull requests
in such branch.
Since version 1.1 we moved development to the traditional "master" branch and we
make use of GitHub's tags and release system to reference development milestones
in time.

Release Versioning
==================

Cuckoo releases are named using three numbers separated by dots, such as 1.2.3,
where the first number is the release, the second number is the major version,
the third number is the bugfix version.
The testing stage from git ends with "-beta" and development stage with "-dev".

    .. warning::

        If you are using a "beta" or "dev" stage, please consider that it's not
        meant to be an official release, therefore we don't guarantee its functioning
        and we don't generally provide support.
        If you think you encountered a bug there, make sure that the nature of the
        problem is not related to your own misconfiguration and collect all the details
        to be notified to our developers. Make sure to specify which exact version you
        are using, eventually with your current git commit id.

Ticketing system
================

To submit bug reports or feature requests, please use GitHub's `Issue`_ tracking
system.

.. _`Issue`: https://github.com/cuckoosandbox/cuckoo/issues

Contribute
==========

To submit your patch just create a Pull Request from your GitHub fork.
If you don't now how to create a Pull Request take a look to `GitHub help`_.

.. _`GitHub help`: https://help.github.com/articles/using-pull-requests/
