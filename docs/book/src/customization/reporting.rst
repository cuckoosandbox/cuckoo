=================
Reporting Modules
=================

After the raw analysis results have been processed and abstracted by the
processing modules and the global container is generated (ref. :doc:`processing`),
it is passed over by Cuckoo to all the reporting modules available, which will
make use of it and will make it accessible and consumable in different
formats.

Getting Started
===============

All reporting modules must be placed inside the directory *modules/reporting/*.

Every module must also have a dedicated section in the file *conf/reporting.conf*: for
example if you create a module *module/reporting/foobar.py* you will have to append
the following section to *conf/reporting.conf*::

    [foobar]
    enabled = on

Every additional option you add to your section will be available to your reporting module
in the ``self.options`` dictionary.

Following is an example of a working JSON reporting module:

    .. code-block:: python
        :linenos:

        import os
        import json
        import codecs

        from lib.cuckoo.common.abstracts import Report
        from lib.cuckoo.common.exceptions import CuckooReportError

        class JsonDump(Report):
            """Saves analysis results in JSON format."""

            def run(self, results):
                """Writes report.
                @param results: Cuckoo results dict.
                @raise CuckooReportError: if fails to write report.
                """
                try:
                    report = codecs.open(os.path.join(self.reports_path, "report.json"), "w", "utf-8")
                    json.dump(results, report, sort_keys=False, indent=4)
                    report.close()
                except (UnicodeError, TypeError, IOError) as e:
                    raise CuckooReportError("Failed to generate JSON report: %s" % e)

This code is very simple, it basically just receives the global container produced by the
processing modules, converts it into JSON and writes it to a file.

There are few requirements for writing a valid reporting module:

    * Declare your class inheriting from ``Report``.
    * Have a ``run()`` function performing the main operations.
    * Try to catch most exceptions and raise ``CuckooReportError`` to notify the issue.

All reporting modules have access to some attributes:

    * ``self.analysis_path``: path to the folder containing the raw analysis results (e.g. *storage/analyses/1/*)
    * ``self.reports_path``: path to the folder where the reports should be written (e.g. *storage/analyses/1/reports/*)
    * ``self.conf_path``: path to the *analysis.conf* file of the current analysis (e.g. *storage/analyses/1/analysis.conf*)
    * ``self.options``: a dictionary containing all the options specified in the report's configuration section in *conf/reporting.conf*.
