=================
Development Notes
=================

Git branches
============

Cuckoo Sandbox source code is available in our `official git repository`_ and
divided in branches

* `Development`: This is where developers work to create the next Cuckoo. 
Here you can see in real time how Cuckoo evolves. Anyway, as development branch,
this can be really unstable and sometimes it may be broken (a checkout may not
work to complete an analysis).
If you want to contribute this branch is for you, so you will be always updated
with Cuckoo official developments.
Users are discouraged to adopt this branch, this is aimed only to developers or
guys with a deep Cuckoo's knowledge.
* `Testing`: When work on development branch is stable enough and a bunch of
features or bug fixes are committed, development branch in merged in testing
branch.
This branch is a testing (or beta) branch, where users can preview and test the
next release.
If you want to be always on the cutting edge this branch is for you.
* `Stable`: When unstable branch is widely tested and without bugs, if all
planned features has been developed a new stable version will be released.

.. _`official git repository`: http://github.com/cuckoobox/cuckoo
.. _`Development`: http://github.com/cuckoobox/cuckoo/tree/development
.. _`Testing`: http://github.com/cuckoobox/cuckoo/tree/testing
.. _`Stable`: http://github.com/cuckoobox/cuckoo
