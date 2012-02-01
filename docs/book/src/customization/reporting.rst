=================
Reporting Results
=================

The *processor* script is responsible for taking analysis results and elaborate them,
as explained in the :doc:`processing` chapter.

Since version 0.3, Cuckoo Sandbox provides also a reporting engine that can be used
to generate consumable reports (as done by the default *processor* script): it takes
the analysis results as input and stores the produced reports in the dedicated folder
as explained in the :doc:`../usage/results` chapter.

The reporting engine, called ``ReportProcessor``, is designed to load all reporting modules
specified in configuration file *reporting.conf* (see :doc:`../installation/host/configuration` chapter) and
execute them.

A reporting module is a simple Python script which aggregates, normalizes and correlates 
analysis data in order to generate a report out of it. Cuckoo comes with several built-in
reporting modules described below, but writing your own modules is incredibly simple.

Built-in Reports
================

Reports for humans
------------------

These reports are developed for end users.

Report TXT
++++++++++

This module generates a human-readable report in plain text format.

Report HTML
+++++++++++

This module generates a human-readable report in HTML format. These reports are also
served by the built-in web server as explained in :doc:`../usage/web`.

MAEC Reports
------------

Malware Attribute Enumeration and Characterization or simply `MAEC <http://maec.mitre.org/>`_
is a standardized language developed by `MITRE <http://www.mitre.org/>`_ to describe malicious
artifacts and their behavior.
According to `MAEC website <http://maec.mitre.org/about/index.html>`_ it can be defined as:

A standardized language for encoding and communicating high-fidelity information about malware
based upon attributes such as behaviors, artifacts, and attack patterns.
By eliminating the ambiguity and inaccuracy that currently exists in malware descriptions and
by reducing reliance on signatures, MAEC aims to improve human-to-human, human-to-tool,
tool-to-tool, and tool-to-human communication about malware; reduce potential duplication of
malware analysis efforts by researchers and allow a faster development of countermeasures
by enabling the ability to leverage responses to previously observed malware instances.

Generating malware analysis in MAEC format brings some benefits to individuals and communities:

* Standard representation: different tools can handle the same malware data without data conversion, tool-to-tool communication is easy.
* Data exchange: individuals and groups can exchange malware analyses in a common, well known and standardized language which helps cooperation between parties.
* Ambiguity loss: an high-fidelity language reduces communication misunderstaning.

MAEC Malware Metadata Sharing
+++++++++++++++++++++++++++++

Cuckoo supports MAEC 1.1 Malware Metadata Sharing reports. 
MAEC Malware Metadata Sharing is a schema for sharing data associated with malicious software 
as defined in `metadataSharing.xsd <http://maec.mitre.org/language/version1.1/xsddocs/http___xml_metadataSharing.xsd/index.html>`_.

MAEC Bundle Report
++++++++++++++++++

Cuckoo supports MAEC 1.1 Bundle reports.
The MAEC schema (or report) is a set of attributes that characterize a malware using a 
predefined language, as defined by MITRE:

The primary intent of the MAEC Schema is to define a syntax for the discrete MAEC Language
elements. The schema also serves as an interchange format for the MAEC Language, and can be
utilized as a baseline for the creation of malware repositories or intermediate format for
the sharing of information between repositories.
The revision 1.1 of the schema has four key types: analyses, actions, objects, and behaviors. 
For more detailed information on these and other types, please refer to the MAEC Schema itself
or its associated HTML documentation.

Data exports
------------

These reports are developed to export analysis data in a standard format to exchange 
data in tool-to-tool communication.

JSON Dump
+++++++++

This module dumps all Cuckoo's analysis results in JSON format.

Writing your own reporting module
=================================

As said, reporting tasks are handled by the ``ReportProcessor`` class: it loads all
reporting modules from *cuckoo/reporting/tasks* folder, checks if they are enabled
in the configuration file and then execute them.

If you want to write your own reporting module you have to:

    * Create a Python file inside the reporting module folder (*cuckoo/reporting/tasks*),
      e.g. *foo.py*.
    * Append an option inside the reporting configuration file (*reporting.conf*) with
      the lowercase name of the file and enable it, like following::
       
        foo = on
       
    * Inside your Python script you have to implement the ``BaseObserver`` interface in a
      class named "``Report``". When new analysis results are available, Cuckoo calls your 
      ``update()`` method passing the analysis results as a parameter.
       
A sample custom reporting module would look like following:

    .. code-block:: python
        :linenos:

        from cuckoo.reporting.observers import BaseObserver

        class Report(BaseObserver):
                
            def update(self, results):
                # Here you get analysis results as parameter.
                # Now do your stuff.
                print "My report!"
 
Whatever operation you might want to run, remember to place it inside the ``update()`` method
or invoke it from there, so that Cuckoo will be able to execute it when needed.

The BaseObserver will check for reports folder and puts that path in self.report_path,
you can use this variable if you need the reports folder path writing your custom report to disk.
