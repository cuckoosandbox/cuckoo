=================
Cuckoo Code Style
=================

All Cuckoo Sandbox code must follow the code style described in this chapter.
Essentially Cuckoo code style is based on `PEP 8 - Style Guide for Python Code
<http://www.python.org/dev/peps/pep-0008/>`_ and `PEP 257 -- Docstring
Conventions <http://www.python.org/dev/peps/pep-0257/>`_.

Formatting
==========

Cuckoo source code files must be written in the following format.

Copyright header
----------------

All source code files must start with copyright header.

Indentation
-----------

Use only 4 spaces per indentation level.

Maximum Line Length
-------------------

Limit all lines to a maximum of 79 characters.

Blank Lines
-----------
Separate top-level function and class definitions with two blank lines.
Method definitions inside a class are separated by a single blank line.
Use blank lines in functions, sparingly, to indicate logical sections.
Import blocks are separated by a single blank line, import blocks are separeted
from classes by two blank lines.

Imports
-------

Imports should usually be on separate lines.

Strings
-------

Strings must be delimited by double quotes (").

Printing strings
----------------

Use only print with brackets, for example::

    print("foo")

Checking for key in data structures
-----------------------------------

When checking for a key in a data structure use the clause "in" instead of
methods like "has_key()", for example::

    if "bar" in foo:
        do_something()

Exceptions
==========

All exceptions must be defined in exceptions.py file.

Naming
------

Custom exception name must prefix with "Cuckoo" and end with "Error" if it's
related to an error.

Exception handling
------------------
When dealing with exceptions we use the "as" instread of "," and the local
variable name is "e". As in the example::

    try:
        foo()
    except Exception as e:
        bar()

Logging
=======

Format
------

End log line always with a dot.

Documentation
=============

All code must be documented in docstring format, see `PEP 257 -- Docstring
Conventions <http://www.python.org/dev/peps/pep-0257/>`_.
Additional comments may be added in logical blocks will be results hard to
understand.
