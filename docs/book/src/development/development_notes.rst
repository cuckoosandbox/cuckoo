=================
Development Notes
=================

Git branches
============

Cuckoo Sandbox source code is available in our `official git repository`_.
You'll find multiple branches which are used for different stages of our
development lifecycle.

    * **Development**: This is where our developers commit their ongoing work for the upcoming releases. As a development branch, this can be really unstable and sometimes even broken and not usable. Users are discouraged to adopt this branch, this is aimed only to developers or guys with a deep knowledge into our technologies.
    * **Testing**: When work on development branch is in a usable state and some new features or fixes are completed, the development branch in merged into testing. This is the branch where users can get a taste of the next release. If you want to be always up-to-date this branch is for you.
    * **Stable**: When unstable branch is widely tested and bugs free and if all planned features has been completed, a new stable version will be released and available here.

.. _`official git repository`: http://github.com/cuckoobox/cuckoo
.. _`Development`: http://github.com/cuckoobox/cuckoo/tree/development
.. _`Testing`: http://github.com/cuckoobox/cuckoo/tree/testing
.. _`Stable`: http://github.com/cuckoobox/cuckoo

Release Versioning
==================

Cuckoo releases are named using three numbers separated by dots, such as 1.2.3, where the first number is the release, the second number is the major version, the third number is the bugfix version.
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

To submit bug reports or feature requests, please use GitHub's `Issue`_ tracking system.

.. _`Issue`: https://github.com/cuckoobox/cuckoo/issues

Contribute
==========

To submit your patch just create a Pull Request from yuor GitHub fork.
If you don't now how to create a Pull Request take a look to `GitHub help`_.

.. _`GitHub help`: https://help.github.com/articles/using-pull-requests/