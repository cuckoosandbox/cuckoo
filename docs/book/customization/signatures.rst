==========
Signatures
==========

With Cuckoo you're able to create some customized signatures that you can run against
the analysis results in order to identify some predefined pattern that might
represent a particular malicious behavior or an indicator you're interested in.

These signatures are very useful to give a context to the analyses: both because they
simplify the interpretation of the results as well as for automatically identifying
malware samples of interest.

Some examples of what you can use Cuckoo's signatures for:

* Identify a particular malware family you're interested in by isolating some unique behaviors (like file names or mutexes).
* Spot interesting modifications the malware performs on the system, such as installation of device drivers.
* Identify particular malware categories, such as Banking Trojans or Ransomware by isolating typical actions commonly performed by those.
* Classify samples into the categories malware/unknown (it is not possible to identify clean samples)

You can find signatures created by us and by other Cuckoo users on our
`Community`_ repository.

.. _`Community`: https://github.com/cuckoosandbox/community

Getting started
===============

Creation of signatures is a fairly simple process and requires just a decent
understanding of Python programming.

First things first, all signatures must be located inside the
``cuckoo/cuckoo/signatures/`` directory in Cuckoo or the
``modules/signatures/`` directory of the `Community`_ repository (the Community
repository is still using legacy directory structuring).

The following is a basic example signature:

.. code-block:: python
    :linenos:

    from cuckoo.common.abstracts import Signature

    class CreatesExe(Signature):
        name = "creates_exe"
        description = "Creates a Windows executable on the filesystem"
        severity = 2
        categories = ["generic"]
        authors = ["Cuckoo Developers"]
        minimum = "2.0"

        def on_complete(self):
            return self.check_file(pattern=".*\\.exe$", regex=True)

As you can see the structure is really simple and consistent with the other
modules. We're going to get into details later, but since version 1.2 Cuckoo
provides some helper functions that make the process of
creating signatures much easier.

In this example we just walk through all the accessed files in the summary and check
if there is anything ending with "*.exe*": in that case it will return ``True``, meaning that
the signature matched, otherwise return ``False``.

The function ``on_complete`` is called at the end of the cuckoo signature process.
Other function will be called before on specific events and help you to write
more sophisticated and faster signatures.

In case the signature gets matched, a new entry in the "signatures" section
will be added to the global container roughly as follows::

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
    ]


Creating your new signature
===========================

In order to make you better understand the process of creating a signature, we
are going to create a very simple one together and walk through the steps and
the available options. For this purpose, we're simply going to create a
signature that checks whether the malware analyzed opened a mutex named
"i_am_a_malware".

The first thing to do is import the dependencies, create a skeleton and define
some initial attributes. These are the ones you can currently set:

    * ``name``: an identifier for the signature.
    * ``description``: a brief description of what the signature represents.
    * ``severity``: a number identifying the severity of the events matched (generally between 1 and 3).
    * ``categories``: a list of categories that describe the type of event being matched (for example "*banker*", "*injection*" or "*anti-vm*").
    * ``families``: a list of malware family names, in case the signature specifically matches a known one.
    * ``authors``: a list of people who authored the signature.
    * ``references``: a list of references (URLs) to give context to the signature.
    * ``enable``: if set to False the signature will be skipped.
    * ``alert``: if set to True can be used to specify that the signature should be reported (perhaps by a dedicated reporting module).
    * ``minimum``: the minimum required version of Cuckoo to successfully run this signature.
    * ``maximum``: the maximum required version of Cuckoo to successfully run this signature.

In our example, we would create the following skeleton:

.. code-block:: python
    :linenos:

    from cuckoo.common.abstracts import Signature

    class BadBadMalware(Signature): # We initialize the class inheriting Signature.
        name = "badbadmalware" # We define the name of the signature
        description = "Creates a mutex known to be associated with Win32.BadBadMalware" # We provide a description
        severity = 3 # We set the severity to maximum
        categories = ["trojan"] # We add a category
        families = ["badbadmalware"] # We add the name of our fictional malware family
        authors = ["Me"] # We specify the author
        minimum = "2.0" # We specify that in order to run the signature, the user will simply need Cuckoo 2.0

        def on_complete(self):
            return

This is a perfectly valid signature. It doesn't really do anything yet,
so now we need to define the conditions for the signature to be matched.

As we said, we want to match a particular mutex name, so we proceed as follows:

.. code-block:: python
    :linenos:

    from cuckoo.common.abstracts import Signature

    class BadBadMalware(Signature):
        name = "badbadmalware"
        description = "Creates a mutex known to be associated with Win32.BadBadMalware"
        severity = 3
        categories = ["trojan"]
        families = ["badbadmalware"]
        authors = ["Me"]
        minimum = "2.0"

        def on_complete(self):
            return self.check_mutex("i_am_a_malware")

Simple as that, now our signature will return ``True`` whether the analyzed
malware was observed opening the specified mutex.

If you want to be more explicit and directly access the global container,
you could translate the previous signature in the following way:

.. code-block:: python
    :linenos:

    from cuckoo.common.abstracts import Signature

    class BadBadMalware(Signature):
        name = "badbadmalware"
        description = "Creates a mutex known to be associated with Win32.BadBadMalware"
        severity = 3
        categories = ["trojan"]
        families = ["badbadmalware"]
        authors = ["Me"]
        minimum = "2.0"

        def on_complete(self):
            for process in self.get_processes_by_pid():
                if "summary" in process and "mutexes" in process["summary"]:
                    for mutex in process["summary"]["mutexes"]:
                        if mutex == "i_am_a_malware":
                            return True

            return False

Evented Signatures
==================

Since version 1.0, Cuckoo provides a way to write more high performance
signatures. In the past every signature was required to loop through the whole
collection of API calls collected during the analysis. This was unnecessarily
causing performance issues when such collection would be of a large size.

Since 1.2 Cuckoo only supports the so called "evented signatures". The old
signatures based on the ``run`` function can be ported to using
``on_complete``. The main difference is that with this new format, all the
signatures will be executed in parallel and a callback function called
``on_call()`` will be invoked for each signature within one single loop
through the collection of API calls.

An example signature using this technique is the following:

.. code-block:: python
    :linenos:

    from cuckoo.common.abstracts import Signature

    class SystemMetrics(Signature):
        name = "generic_metrics"
        description = "Uses GetSystemMetrics"
        severity = 2
        categories = ["generic"]
        authors = ["Cuckoo Developers"]
        minimum = "2.0"

        # Evented signatures can specify filters that reduce the amount of
        # API calls that are streamed in. One can filter Process name, API
        # name/identifier and category. These should be sets for faster lookup.
        filter_processnames = set()
        filter_apinames = set(["GetSystemMetrics"])
        filter_categories = set()

        # This is a signature template. It should be used as a skeleton for
        # creating custom signatures, therefore is disabled by default.
        # The on_call function is used in "evented" signatures.
        # These use a more efficient way of processing logged API calls.
        enabled = False

        def on_complete(self):
            # In the on_complete method one can implement any cleanup code and
            #  decide one last time if this signature matches or not.
            #  Return True in case it matches.
            return False

        # This method will be called for every logged API call by the loop
        # in the RunSignatures plugin. The return value determines the "state"
        # of this signature. True means the signature matched and False it did not this time.
        # Use self.deactivate() to stop streaming in API calls.
        def on_call(self, call, pid, tid):
            # This check would in reality not be needed as we already make use
            # of filter_apinames above.
            if call["api"] == "GetSystemMetrics":
                # Signature matched, return True.
                return True

            # continue
            return None


The inline comments are already self-explanatory.

Another event is triggered when a signature matches.

.. code-block:: python
    :linenos:
	
    required = ["creates_exe", "badmalware"]

    def on_signature(self, matched_sig):
        if matched_sig in self.required:
            self.required.remove(matched_sig)

        if not self.required:
            return True
	
        return False

This kind of signature can be used to combine several signatures identifying
anomalies into one signature classifying the sample (malware alert).

Marks & Helpers
===============

Starting from version 1.2, signatures are able to log exactly what triggered
the signature. This allows users to better understand why this signature is
present in the log, and to be able to better focus malware analysis.

For examples on marks and helpers please refer to the Cuckoo `Community`_ for
now - until we write some thorough up-to-date documentation on that.
