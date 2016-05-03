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

You can find signatures created by us and by other Cuckoo users on our `Community`_ repository.

.. _`Community`: https://github.com/cuckoosandbox/community

Getting started
===============

Creation of signatures is a very simple process and requires just a decent
understanding of Python programming.

First things first, all signatures must be located inside *modules/signatures/*.

The following is a basic example signature:

    .. code-block:: python
        :linenos:

        from lib.cuckoo.common.abstracts import Signature

        class CreatesExe(Signature):
            name = "creates_exe"
            description = "Creates a Windows executable on the filesystem"
            severity = 2
            categories = ["generic"]
            authors = ["Cuckoo Developers"]
            minimum = "2.0"

            def on_complete(self):
                return self.check_file(pattern=".*\\.exe$",
                                       regex=True)

As you can see the structure is really simple and consistent with the other
modules. We're going to get into details later, but since version 1.2 Cuckoo
provides some helper functions that make the process of
creating signatures much easier.

In this example we just walk through all the accessed files in the summary and check
if there is anything ending with "*.exe*": in that case it will return ``True``, meaning that
the signature matched, otherwise return ``False``.

the function ``on_complete`` is called at the end of the cuckoo signature process.
Other function will be called before on specific events and help you to write
more sophisticated and faster signatures.

In case the signature gets matched, a new entry in the "signatures" section will be added to
the global container as follows::

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

        from lib.cuckoo.common.abstracts import Signature

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

        from lib.cuckoo.common.abstracts import Signature

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

        from lib.cuckoo.common.abstracts import Signature

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

Since version 1.0, Cuckoo provides a way to write more high performance signatures.
In the past every signature was required to loop through the whole collection of API calls
collected during the analysis. This was necessarily causing some performance issues when such
collection would be of a large size.

Since 1.2 Cuckoo only supports the so called "evented signatures". The old signatures
based on the ``run`` function can be ported to using ``on_complete``.
The main difference is that with this new format, all the signatures will be executed in parallel
and a callback function called ``on_call()`` will be invoked for each signature within one
single loop through the collection of API calls.

An example signature using this technique is the following:

    .. code-block:: python
        :linenos:

        from lib.cuckoo.common.abstracts import Signature

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

        def on_signature(self, matched_sig):
            required = ["creates_exe", "badmalware"]
            for sig in required:
                if not sig in self.list_signatures():
                    return
            return True

This kind of signature can be used to combine several signatures identifying anomalies into one signature
classifying the sample (malware alert).

Two more events can be used to write more complex signatures. They are called when new processes are processed or new threads.
``on_process`` and ``on_thread``. They can be used to reset the state of flags when a new process is entered. Allowing
to write signatures that take into account if a series of events happened in one thread/process or globally.

.. code-block:: python
        :linenos:

        def on_process(self, pid):
            pass

        def on_thread(self, pid, tid):
            pass

Quickout
========
Additionally to the filters you can use a quickout function to determine if the
signature can be matched at all. For example if a signature is written to identify
behavior of malicious PDFs you could test for the file type to be PDF. Returning ``True`` will
remove the signature from the list of potential candidates (reducing False Positives and processing time).

You can find many more example of signatures in our `community repository`_.

.. _`community repository`: https://github.com/cuckoosandbox/community

Matches
=======

Starting from version 1.2, signatures are able to log exactly what triggered
the signature. This allows users to better understand why this signature is
present in the log, and to be able to better focus malware analysis.

Two helpers have been included in order to specify matching data.

.. function:: Signature.add_match(process, type, match)

    Adds a match to the signature. Can be called several times for the same signature.

    :param process: process dictionary (same as the ``on_call`` argument). Should be ``None`` except when used in evented signatures.
    :type process: dict
    :param type: nature of the matching data. Can be anything (ex: ``'file'``, ``'registry'``, etc.). If match is composed of api calls (when used in evented signatures), should be ``'api'``.
    :type type: string
    :param match: matching data. Can be a single element or a list of elements. An element can be a string, a dict or an API call (when used in evented signatures).

    Example Usage, with a single element:

    .. code-block:: python
        :linenos:

        self.add_match(None, "url", "http://malicious_url_detected.com")

    Example Usage, with a more complex signature, needing several API calls to be triggered:

    .. code-block:: python
        :linenos:

        self.signs = []
        self.signs.append(first_api_call)
        self.signs.append(second_api_call)
        self.add_match(process, 'api', self.signs)

.. function:: Signature.has_matches()

    Checks whether the current signature has any matching data registered. Returns ``True`` in case it does, otherwise returns ``False``.

    This can be used to easily add several matches for the same signature. If you want to do so, make sure that all the api calls are scanned by making sure that ``on_call`` never returns ``True``. Then, use ``on_complete`` with ``has_matches`` so that the signature is triggered if any match was previously added.

    :rtype: boolean

    Example Usage, from the `network_tor` signature:

    .. code-block:: python
        :linenos:

        def on_call(self, call, process):
            if self.check_argument_call(call,
                                        pattern="Tor Win32 Service",
                                        api="CreateServiceA",
                                        category="services"):
                self.add_match(process, "api", call)

        def on_complete(self):
            return self.has_matches()

Helpers
=======

As anticipated, from version 0.5 the ``Signature`` base class also provides
some helper methods that simplify the creation of signatures and avoid the need
for you having to access the global container directly (at least most of the times).

With Cuckoo 1.2 the amount of information extracted from a sample grew another step and the
resulting data format got more complex. To avoid having to port your signatures with every extension and to reduce
errors we strongly suggest to use the helpers to access data.

Following is a list of available methods.

.. function:: Signature.check_file(pattern[, regex=False])

    Checks whether the malware opened or created a file matching the specified pattern. Returns ``True`` in case it did, otherwise returns ``False``.

    :param pattern: file name or file path pattern to be matched
    :type pattern: string
    :param regex: enable to compile the pattern as a regular expression
    :type regex: boolean
    :rtype: boolean

    Example Usage:

    .. code-block:: python
        :linenos:

        self.check_file(pattern=".*\.exe$", regex=True)

.. function:: Signature.check_key(pattern[, regex=False[, actions=["regkey_written", "regkey_opened", "regkey_read"][, pid=None]]])

    Checks whether the malware opened or created a registry key matching the specified pattern. Returns ``True`` in case it did, otherwise returns ``False``.

    :param pattern: registry key pattern to be matched
    :type pattern: string
    :param regex: enable to compile the pattern as a regular expression
    :type regex: boolean
    :param actions: a list of key-access-actions to search the key in
    :type actions: list
    :param pid: process id to filter for
    :type pid: int
    :rtype: boolean

    Example Usage:

    .. code-block:: python
        :linenos:

        self.check_key(pattern=".*CurrentVersion\\Run$", regex=True)

.. function:: Signature.check_mutex(pattern[, regex=False])

    Checks whether the malware opened or created a mutex matching the specified pattern. Returns ``True`` in case it did, otherwise returns ``False``.

    :param pattern: mutex pattern to be matched
    :type pattern: string
    :param regex: enable to compile the pattern as a regular expression
    :type regex: boolean
    :rtype: boolean

    Example Usage:

    .. code-block:: python
        :linenos:

        self.check_mutex("mutex_name")

.. function:: Signature.check_api(pattern[, process=None[, regex=False]])

    Checks whether Windows function was invoked. Returns ``True`` in case it was, otherwise returns ``False``.

    :param pattern: function name pattern to be matched
    :type pattern: string
    :param process: name of the process performing the call
    :type process: string
    :param regex: enable to compile the pattern as a regular expression
    :type regex: boolean
    :rtype: boolean

    Example Usage:

    .. code-block:: python
        :linenos:

        self.check_api(pattern="URLDownloadToFileW", process="AcroRd32.exe")

.. function:: Signature.check_argument_call(call, pattern[, name=Name[, api=None[, category=None[, regex=False]]])

    Checks whether the malware invoked a function with a specific argument value. Returns ``True`` in case it did, otherwise returns ``False``.

    :param call: the call to check to check the argument in
    :param pattern: argument value pattern to be matched
    :type pattern: string
    :param name: name of the argument to be matched
    :type name: string
    :param api: name of the Windows function associated with the argument value
    :type api: string
    :param category: name of the category of the function to be matched
    :type category: string
    :param regex: enable to compile the pattern as a regular expression
    :type regex: boolean
    :rtype: boolean

    Example Usage:

    .. code-block:: python
        :linenos:

        self.check_argument_call(call, pattern=".*cuckoo.*", category="filesystem", regex=True)

.. function:: Signatures.list_signatures()

    Returns a list of signature names that matched so far. It can be used to write meta-signatures combining several
    signatures on anomalies into a classification.

    :rtype: list

    Example Usage:

    .. code-block:: python
        :linenos:

        def on_signature(self, matched_sig):
            required = ["creates_exe", "badmalware"]
            for sig in required:
                if not sig in self.list_signatures():
                    return
            return True

.. function:: Signatures.get_processes([name=None])

    An iterator returning the processes monitored. If name is given, they will be filtered for the name

    :param name: Name of the process to filter for
    :type name: string
    :rtype: iterator

    Example Usage:

    .. code-block:: python
        :linenos:

        for process in self.get_processes("foo"):
            pass

.. function:: Signatures.get_processes_by_pid([pid=None])

    An iterator returning the processes monitored. If pid is given, they will be filtered for the process id

    :param pid: Process ID of the process to filter for
    :type pid: int
    :rtype: iterator

    .. code-block:: python
        :linenos:

        for process in self.get_processes_by_pid(4):
            pass

.. function:: Signatures.get_threads([pid=None])

    An iterator returning the threads monitored. If pid is given, they will be filtered for the process id.

    :param pid: Name of the process to filter for
    :type pid: int
    :rtype: iterator

    .. code-block:: python
        :linenos:

        for thread in self.get_threads():
            pass

.. function:: Signatures.get_files([pid=None,[actions=None]])

    Iterates over the files accessed by a process (or all processes). Access type can be a list of "file_written",
    "file_read", "file_deleted". Default is all.

    :param pid: Name of the process to filter for
    :type pid: int
    :param actions: access types of the files to return
    :type actions: list
    :rtype: iterator

    .. code-block:: python
        :linenos:

        for afile in self.get_files():
            pass

.. function:: Signatures.get_keys([pid=None,[actions=None]])

    Iterates over the registry keys accessed by a process (or all processes). Access type can be a list of "regkey_written",
    "regkey_opened", "regkey_read". Default is all.

    :param pid: Name of the process to filter for
    :type pid: int
    :param actions: access types of the registry keys to return
    :type actions: list
    :rtype: iterator

    .. code-block:: python
        :linenos:

        for akey in self.get_keys():
            pass

.. function:: Signatures.get_mutexes([pid=None])

    Returns a list of mutexes. Optionally filtered by process id

    :param pid: Name of the process to filter for
    :type pid: int
    :rtype: list

    .. code-block:: python
        :linenos:

        for mutex in self.get_mutexes():
            pass

.. function:: Signature.get_net_hosts()

    Returns a list of hosts from the network sniffing part of the collected data

    :rtype: list

    .. code-block:: python
        :linenos:

        for host in self.get_net_hosts():
            pass

.. function:: Signature.get_net_domains()

    Returns a list of domains from the network sniffing part of the collected data

    :rtype: list

    .. code-block:: python
        :linenos:

        for domain in self.get_net_domains():
            pass

.. function:: Signature.get_net_http()

    Returns a list of http information blocks from the network sniffing part of the collected data

    :rtype: list

    .. code-block:: python
        :linenos:

        for http_data in self.get_net_http():
            pass

.. function:: Signature.get_net_udp()

    Returns a list of udp information blocks from the network sniffing part of the collected data

    :rtype: list

    .. code-block:: python
        :linenos:

        for udp_data in self.get_net_udp():
            pass

.. function:: Signature.get_net_icmp()

    Returns a list of icmp information blocks from the network sniffing part of the collected data

    :rtype: list

    .. code-block:: python
        :linenos:

        for icmp_data in self.get_net_icmp():
            pass

.. function:: Signature.get_net_irc()

    Returns a list of irc information blocks from the network sniffing part of the collected data

    :rtype: list

    .. code-block:: python
        :linenos:

        for irc_data in self.get_net_irc():
            pass

.. function:: Signature.get_net_smtp()

    Returns a list of smtp information blocks from the network sniffing part of the collected data

    :rtype: list

    .. code-block:: python
        :linenos:

        for smtp_data in self.get_net_smtp():
            pass

.. function:: Signature.check_ip(pattern[, regex=False])

    Checks whether the malware contacted the specified IP address. Returns ``True`` in case it did, otherwise returns ``False``.

    :param pattern: IP address to be matched
    :type pattern: string
    :param regex: enable to compile the pattern as a regular expression
    :type regex: boolean
    :rtype: boolean

    Example Usage:

    .. code-block:: python
        :linenos:

        self.check_ip("123.123.123.123")

.. function:: Signature.check_domain(pattern[, regex=False])

    Checks whether the malware contacted the specified domain. Returns ``True`` in case it did, otherwise returns ``False``.

    :param pattern: domain name to be matched
    :type pattern: string
    :param regex: enable to compile the pattern as a regular expression
    :type regex: boolean
    :rtype: boolean

    Example Usage:

    .. code-block:: python
        :linenos:

        self.check_domain(pattern=".*cuckoosandbox.org$", regex=True)

.. function:: Signature.check_url(pattern[, regex=False])

    Checks whether the malware performed an HTTP request to the specified URL. Returns ``True`` in case it did, otherwise returns ``False``.

    :param pattern: URL pattern to be matched
    :type pattern: string
    :param regex: enable to compile the pattern as a regular expression
    :type regex: boolean
    :rtype: boolean

    Example Usage:

    .. code-block:: python
        :linenos:

        self.check_url(pattern="^.+\/load\.php\?file=[0-9a-zA-Z]+$", regex=True)

.. function:: Signature.flags.set(name, [pid=None[, tid=None[, timestamp=None]]])

    Flags can be used to collect information in the on_call section of a signature and react (decide to alert) in the
    on_complete part if all required flags are set. Flags are signature specific. They are identified by their name.
    PID, TID and timestamp can be later used to identify if a flag was set in a specific process/thread or at a specific
    time.

    :param name: Name of the flag to set
    :type name: string
    :param pid: process id
    :type pid: int
    :param tid: thread id
    :type tid: int
    :param timestamp: timestamp in the log to mark this flag for
    :type timestamp: int

    .. code-block:: python
        :linenos:

        def on_call(self, call, pid, tid):
            self.flags.set("foo", 1, 2, 2345)

.. function:: Signature.flags.find([name=None[, pid=None[, tid=None[, before=None[, after=None]]]])

    Returns a list of flags matching the given criteria

    :param name: Name of the flag look for
    :type name: string
    :param pid: process id to filter for
    :type pid: int
    :param tid: thread id to filter for
    :type tid: int
    :param before: flag timestamp must be <= before-timestamp
    :type before: int
    :param after: flag timestamp must be >= after-timestamp
    :type after: int

    .. code-block:: python
        :linenos:

        def on_complete(self):
            if self.flags.find("foo"):
                self.data.append({"Flag found matching name": "foo"})
                return True

.. function:: Signature.mark_start()

    Mark the start of a api-call region relevant for the signature. This way the report can contain a link to the API call that triggered the signature.
    As soon as the signature returns ``True`` this mark will be stored in the report. Subsequent start marks will overwrite the old one till it is
    stored in the results with the triggering of the signature. So you can set a start mark "on suspicion" and overwrite it several times till the signature triggers.

    It is marking the api call. So the only reasonable signatures to use it is in on_call evented ones

    .. code-block:: python
        :linenos:

        def on_call(self, call, pid, tid):
            if self.check_argument_call(call, pattern=".*cuckoo.*", category="filesystem", regex=True):
                self.mark_start()
                return True

.. function:: Signature.mark_end()

    A complementary function to mark_start. It is optional and marks the end of a api call range that triggered the signature. It should be
    called before returning the ``True`` result.

    Without a prior mark_start, the end-mark will not be stored in the result.

    .. code-block:: python
        :linenos:

        def on_call(self, call, pid, tid):
            if self.check_argument_call(call, pattern=".*foo.*", category="filesystem", regex=True):
                self.mark_start()
                return None
            if self.check_argument_call(call, pattern=".*cuckoo.*", category="filesystem", regex=True):
                self.mark_end()
                return True

.. function:: Signature.deactivate()

    Deactivate a signature. Deactivated signatures will not be notified in ``on_call`` events. This can be used after a
    signature triggered (just before the return) to match this signature only once.

    .. code-block:: python
        :linenos:

        def on_call(self, call, pid, tid):
            if call["api"] == "LdrGetProcedureAddress":
                self.deactivate()
                return True


.. function:: Signature.activate()

    Re-activates a signature after it has been de-activated.

    .. code-block:: python
        :linenos:

        def on_process(self, pid):
            self.activate()
