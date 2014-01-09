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
    * Memory dumps of the malware processes.
    * Network traffic trace in PCAP format.
    * Screenshots of Windows desktop taken during the execution of the malware.
    * Full memory dumps of the machines.

Some History
============

Cuckoo Sandbox started as a `Google Summer of Code`_ project in 2010 within
`The Honeynet Project`_.
It was originally designed and developed by *Claudio “nex” Guarnieri*, who is
still the main developer and coordinates all efforts from joined developers and
contributors.

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

On December 2011 Cuckoo v0.3 gets released and quickly hits release 0.3.2 in
early February.

In late January 2012 we opened `Malwr.com`_, a free and public running Cuckoo
Sandbox instance provided with a full fledged interface through which people
can submit files to be analysed and get results back.

In March 2012 Cuckoo Sandbox wins the first round of the `Magnificent7`_ program
organized by `Rapid7`_.

During the Summer of 2012 *Jurriaan "skier" Bremer* joined the development team,
refactoring the Windows analysis component sensibly improving the analysis'
quality.

On 24th July 2012, Cuckoo Sandbox 0.4 is released.

On 20th December 2012, Cuckoo Sandbox 0.5 "To The End Of The World" is released.

On 15th April 2013 we released Cuckoo Sandbox 0.6, shortly after having launched
the second version of `Malwr.com`_.

On 1st August 2013 *Claudio “nex” Guarnieri*, *Jurriaan "skier" Bremer* and
*Mark "rep" Schloesser* presented `Mo' Malware Mo' Problems - Cuckoo Sandbox to the rescue`_
at Black Hat Las Vegas.

On 9th January 2014, Cuckoo Sandbox 1.0 is released.

.. _`Google Summer of Code`: http://www.google-melange.com
.. _`The Honeynet Project`: http://www.honeynet.org
.. _`Malwr.com`: http://malwr.com
.. _`Magnificent7`: http://community.rapid7.com/community/open_source/magnificent7
.. _`Mo' Malware Mo' Problems - Cuckoo Sandbox to the rescue`: https://media.blackhat.com/us-13/US-13-Bremer-Mo-Malware-Mo-Problems-Cuckoo-Sandbox-Slides.pdf
.. _`Rapid7`: http://www.rapid7.com

Use Cases
=========

Cuckoo is designed to be used both as a standalone application as well as to be
integrated in larger frameworks, thanks to its extremely modular design.

It can be used to analyze:

    * Generic Windows executables
    * DLL files
    * PDF documents
    * Microsoft Office documents
    * URLs and HTML files
    * PHP scripts
    * CPL files
    * Visual Basic (VB) scripts
    * ZIP files
    * Java JAR
    * *Almost anything else*

Thanks to its modularity and powerful scripting capabilities, there's not limit
to what you can achieve with Cuckoo.

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
analysis process, while the Guests are the isolated environments
where the malwares get actually safely executed and analyzed.

The following picture explains Cuckoo's main architecture:

    .. image:: ../_images/schemas/architecture-main.png
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

.. _`official website`: http://www.cuckoosandbox.org
.. _`official git repository`: http://github.com/cuckoobox/cuckoo

