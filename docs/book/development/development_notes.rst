=================
Development Notes
=================

Git branches
============

Cuckoo Sandbox source code is available in our `official Git repository`_.

.. _`official git repository`: https://github.com/cuckoosandbox/cuckoo

Up until version 1.0 we used to coordinate all ongoing development in a
dedicated "development" branch and we've been exclusively merging pull
requests in such branch.
Since version 1.1 we moved development to the traditional "master" branch and
we make use of GitHub's tags and release system to reference development
milestones in time.

Release Versioning
==================

At the moment we utilize three types of releases:
* 1.2.3, an official release, preferably accompanied by a blogpost
* 1.2.4a1, an alpha release that showcases functionality that will be present in the upcoming release
* 1.2.3.1, a hotfix release, meant to fix critical issues, usually found in the latest official release

Ticketing system
================

To submit bug reports or feature requests, please use GitHub's `Issue`_
tracking system.

.. _`Issue`: https://github.com/cuckoosandbox/cuckoo/issues

Contribute
==========

To submit your patch just create a Pull Request from your GitHub fork.
If you don't now how to create a Pull Request take a look to `GitHub help`_.

.. _`GitHub help`: https://help.github.com/articles/using-pull-requests/
