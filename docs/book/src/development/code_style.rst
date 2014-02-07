============
Coding Style
============

In order to contribute code to the project, you must diligently follow the
style rules describe in this chapter. Having a clean and structured code is
very important for our development lifecycle, and not compliant code will
most likely be rejected.

Essentially Cuckoo's code style is based on `PEP 8 - Style Guide for Python Code
<http://www.python.org/dev/peps/pep-0008/>`_ and `PEP 257 -- Docstring
Conventions <http://www.python.org/dev/peps/pep-0257/>`_.

Formatting
==========

Copyright header
----------------

All source code files must start with the following copyright header::

    # Copyright (C) 2010-2014 Cuckoo Sandbox Developers.
    # This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
    # See the file 'docs/LICENSE' for copying permission.

Indentation
-----------

The code must have a 4-spaces-tabs indentation.
Since Python enforce the indentation, make sure to configure your editor
properly or your code might cause malfunctioning.

Maximum Line Length
-------------------

Limit all lines to a maximum of 79 characters.

Blank Lines
-----------

Separate the class definition and the top level function with one blank line.
Methods definitions inside a class are separated by a single blank line::

    class MyClass:
        """Doing something."""

        def __init__(self):
            """Initialize"""
            pass

        def do_it(self, what):
            """Do it.
            @param what: do what.
            """
            pass

Use blank lines in functions, sparingly, to isolate logic sections.
Import blocks are separated by a single blank line, import blocks are separeted
from classes by one blank line.

Imports
-------

Imports must be on separate lines. If you're importing multiple objects from a
package, use a single line::

    from lib import a, b, c

**NOT**::

    from lib import a
    from lib import b
    from lib import c

Always specify explicitly the objects to import::

    from lib import a, b, c

**NOT**::

    from lib import *

Strings
-------

Strings must be delimited by double quotes (").

Printing and Logging
--------------------

We discourage the use of ``print()``: if you need to log an event please use
Python's ``logging`` which is already initialized by Cucoko.

In your module add::

    import logging
    log = logging.getLogger(__name__)

And use the ``log`` handle, refer to Python's documentation.

In case you really need to print a string to standard output, use the 
``print()`` function::

    print("foo")

**NOT** the statement::

    print "foo"

Checking for keys in data structures
------------------------------------

When checking for a key in a data structure use the clause "in" instead of
methods like "has_key()", for example::

    if "bar" in foo:
        do_something(foo["bar"])

Exceptions
==========

Custom exceptions must be defined in the *lib/cuckoo/common/exceptions.py* file
or in the local module if the exception should not be global.

Following is current Cuckoo's exceptions chain::

    .-- CuckooCriticalError
    |   |-- CuckooStartupError
    |   |-- CuckooDatabaseError
    |   |-- CuckooMachineError
    |   `-- CuckooDependencyError
    |-- CuckooOperationalError
    |   |-- CuckooAnalysisError
    |   |-- CuckooProcessingError
    |   `-- CuckooReportError
    `-- CuckooGuestError

Beware that the use of ``CuckooCriticalError`` and its child exceptions will
cause Cuckoo to terminate.

Naming
------

Custom exceptions name must prefix with "Cuckoo" and end with "Error" if it
represents an unexpected malfunction.

Exception handling
------------------

When catching an exception and accessing its handle, use ``as e``::

    try:
        foo()
    except Exception as e:
        bar()

**NOT**::

    try:
        foo()
    except Exception, something:
        bar()

It's a good practice use "e" instead of "e.message", as in the example above.

Documentation
=============

All code must be documented in docstring format, see `PEP 257 -- Docstring
Conventions <http://www.python.org/dev/peps/pep-0257/>`_.
Additional comments may be added in logical blocks will be results hard to
understand.

Automated testing
=================

We belive in automated testing to provide high quality code and avoid dumb
bugs.
When possible, all code must be committed with proper unit tests. Particular
attention must be placed when fixing bugs: it's good practice to write unit
tests to reproduce the bug.
All unit tests and fixtures are placed in the tests folder in the cuckoo
root.
We adopt `Nose <http://nose.readthedocs.org/en/latest/>`_ as unit testing framework.