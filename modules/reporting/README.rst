MAEC v4.1
=========

MAEC is a standardized language for encoding and communicating high-fidelity information about malware based upon attributes such as behaviors, artifacts, and attack patterns.

:Source: https://github.com/MAECProject/python-maec
:Documentation: http://maec.readthedocs.org
:Information: http://maec.mitre.org

|version badge| |downloads badge|

.. TODO: add Travis Badge

.. |version badge| image:: https://pypip.in/v/maec/badge.png
   :target: https://pypi.python.org/pypi/maec/
.. |downloads badge| image:: https://pypip.in/d/maec/badge.png
   :target: https://pypi.python.org/pypi/maec/

Versioning
----------
MAEC v4.1 is dependent upon python-maec >= v4.1.0.8 and python-cybox >= v2.1.0.8.

Installation
------------

The ``maec`` package depends on the following Python libraries: \* ``lxml`` >=
3.1.x \* ``python-cybox`` >= 2.1.x.x \* ``setuptools`` (only if installing
using setup.py)

For Windows installers of the above libraries, we recommend looking here:
http://www.lfd.uci.edu/~gohlke/pythonlibs. python-cybox can be found at
https://github.com/CybOXProject/python-cybox/releases.

To build ``lxml`` on Ubuntu, you will need the following packages from the
Ubuntu package repository:

-  python-dev
-  libxml2-dev
-  libxslt1-dev
