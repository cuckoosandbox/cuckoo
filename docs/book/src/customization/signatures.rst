==========
Signatures
==========

With Cuckoo you're able to create some customized signatures that you can run against
the analysis results in order to identify some predefined pattern that might
represent a particular malicious behavior or an indicator you're interested in.

These signatures are very useful to give a context to the analyses: both because they
simplify the interpretation of the results as well as for automatically identifying
malwares of interest.

Getting started
===============

Creation of signatures is a very simple process and requires just a decent
understanding of Python programming.

All signatures are and should be located in *modules/signatures/*.

A basic example signature is the following:

    .. code-block:: python
        :linenos:

        from lib.cuckoo.common.abstracts import Signature

        class CreatesExe(Signature):
            name = "creates_exe"
            description = "Creates a Windows executable on the filesystem"
            severity = 2

            def run(self, results):
                for file_name in results["behavior"]["summary"]["files"]:
                    if file_name.endswith(".exe"):
                        self.data.append({"file_name" : file_name})
                        return True

                return False

As you can see the structure is very simple and similar to the other modules types
we've seen so far.

You need to declare your class inheriting ``Signature``, for which you can define
some generic attributes:

    * ``name``: an identifier for the signature.
    * ``description``: a brief description of what the signature represents.
    * ``severity``: a number identifying the severity of the events matched (generally between 1 and 3).
    * ``authors``: a list of people who authored the signature.
    * ``references``: a list of references (URLs) to give context to the signature.
    * ``enable``: if set to False the signature will be skipped.
    * ``alert``: if set to True can be used to specify that the signature should be reported (perhaps by a dedicated reporting module)

The ``run()`` function takes the previously generated global container (see :doc:`processing`) and
performs some checks against it.

In the given example it just walks through all the accessed files in the summary and checks
if there is anything ending with ".exe": in that case it will return ``True``, meaning that
the signature was matched. Otherwise return ``False``.

In case the signature gets matched, a new entry in the "signatures" section will be added to
the global container like following::

    "signatures": [
        {
            "severity": 2, 
            "description": "Creates a Windows executable on the filesystem", 
            "alert": false, 
            "references": [], 
            "data": [
                {
                    "file_name": "C:\\d.exe"
                }
            ], 
            "name": "creates_exe"
        }
    ], 
