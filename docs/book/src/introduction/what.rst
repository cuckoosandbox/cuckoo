===============
What is Cuckoo?
===============

Cuckoo is an open source automated malware analysis system.

It's used to automatically run and analyze files and collect comprehensive
analysis results that outline what the malware does while running inside an
isolated Windows operating system.

It can retrieve the following type of results:

    * Traces of win32 API calls performed by all processes spawned by the malware.
    * Files being created, deleted and downloaded by the malware during its execution.
    * Network traffic trace in PCAP format.
    * Screenshots of Windows desktop taken during the execution of the malware.
    * Traces of assembly instructions performed by the malware.

Some History
============

Cuckoo Sandbox started as a `Google Summer of Code`_ project in 2010 within
`The Honeynet Project`_.
It was originally designed and developed by *Claudio “nex” Guarnieri*, who still
mantains it and coordinates all efforts from joined developers and contributors.

After initial work during the summer 2010, the first beta release was published
on Feb. 5th 2011, when Cuckoo was publicly announced and distributed for the
first time.

In March 2011, Cuckoo has been selected again as a supported project during
Google Summer of Code 2011 with The Honeynet Project, during which
*Dario Fernandes* joined the project and extended its functionalities.

On November 2nd 2011 Cuckoo the release of its 0.2 version to the public as the
first real stable release.

On late November 2011 *Alessandro "jekil" Tanasi* joined the team expanding
Cuckoo's processing and reporting functionalities.

On December 2011 Cuckoo v0.3 gets released and quickly hitting release 0.3.2 in
early February.

In late January 2012 we opened `Malwr.com`_, a free and public running Cuckoo
Sandbox instance provided with a full fledged interface through which people
can submit files to be analysed and get results back.

.. _`Google Summer of Code`: http://www.google-melange.com
.. _`The Honeynet Project`: http://www.honeynet.org
.. _`Malwr.com`: http://malwr.com

Use Cases
=========

Cuckoo is designed to be used both as a standalone application as well as to be
integrated in larger frameworks, thanks to its submission and processing
automation capabilities.

It can be used to analyze:

    * Generic Windows executables
    * DLL files
    * PDF documents
    * Microsoft Office documents
    * URLs
    * PHP scripts
    * *Almost everything else*

Thanks to its scripting and customization capabilities there's basically no
limit to what you can achieve with Cuckoo, for example automating malware
unpacking or automating the dump of configuration files and web-injects
from banking trojans.

For more information on customizing Cuckoo, see the :doc:`../customization/index`
chapter.

Architecture
============

Cuckoo Sandbox consists of a central management software which handles sample
execution and analysis.

Each analysis is launched in a fresh and isolated virtual machine.
Cuckoo's infrastructure is composed by an Host machine (the management
software) and a number of Guest machines (virtual machines for analysis).

The Host runs the core component of the sandbox that manages the whole
analysis and execution process, while the Guests are the isolated environments
where the malwares get actually safely executed and analyzed.

The following picture explains Cuckoo's architecture:

    .. figure:: ../_images/schemas/architecture.png
        :align: center

Although recommended setup is *GNU/Linux* (Ubuntu preferrably) as host and
*Windows XP Service Pack 3* as guest, Cuckoo proved to work smoothly also on
*Mac OS X* as host and *Windows Vista* and *Windows 7* as guests.

Obtaining Cuckoo
================

Cuckoo can be downloaded from the `official website`_, where the stable and
packaged releases are distributed, or can be cloned from our `official git
repository`_.

    .. warning::

        While being more updated, including new features and bugfixes, the
        version available in the git repository should be considered an
        *under development* stage. Therefore its stability is not guaranteed
        and it most likely lacks updated documentation.

.. _`official website`: http://www.cuckoobox.org
.. _`official git repository`: http://github.com/cuckoobox/cuckoo

