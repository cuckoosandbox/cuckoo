=====================
Processing of results
=====================

As exaplained in the :doc:`../installation/host/configuration` chapter, once an
analysis is completed, Cuckoo invokes a script which can be used to access and
manipulate the results produced. It's conceived to be customized by the user to
make it do whatever he prefers.

Such script (called "*processor*") is invoked concurrently to Cuckoo,
making it completely independent from the sandbox execution, and takes the path
to the analysis results as argument.


The default processor looks like following:

    .. code-block:: python
        :linenos:

        import sys
        from optparse import OptionParser

        from cuckoo.processing.data import CuckooDict
        from cuckoo.reporting.reporter import ReportProcessor
        from cuckoo.logging.crash import crash

        def main():
            analysis_path = None

            parser = OptionParser(usage="usage: %prog [options] analysispath")
            parser.add_option("-m", "--message",
                              action="store",
                              type="string",
                              dest="message",
                              default=None,
                              help="Specify a message to notify to the processor script")
            parser.add_option("-c", "--custom",
                              action="store",
                              type="string",
                              dest="custom",
                              default=None,
                              help="Specify a custom value to be used by the processor")

            (options, args) = parser.parse_args()

            if len(args) == 1:
                try:
                    analysis_path = args[0]
                except IndexError, why:
                    pass

            if options.message:
                print options.message

            if options.custom:
                print options.custom

            if analysis_path:
                # Generate reports out of abstracted analysis results.
                ReportProcessor(analysis_path).report(CuckooDict(analysis_path).process())

            return True

        if __name__ == "__main__": 
            try:
                main()
            except KeyboardInterrupt:
                print "User aborted."
            except SystemExit:
                pass
            except:
                crash()

What it does is obtain a dictionary out of the raw results and invoke the
generation of the enabled reports as explained in
:doc:`../installation/host/configuration`.

In order to simplify some of the processing tasks you might need to perform,
Cuckoo provide some ready-to-use functions and classes which are generally
located in "*cuckoo/processing/*".

Retrieving details on a file
============================

The first thing you might be interested in, is retrieving some details on the
binary you just analyzed. For this purpose there's a dedicated class called
``File`` provided by the module ``cuckoo.processing.file``. It takes the path
to a file as argument and invoking ``process()`` retrieves a dictionary
containing some static details. You can actually use this clan on any file you
want, perhaps also on dropped files.

Following is an example usage and output:

    .. code-block:: python

        >>> import pprint
        >>> from cuckoo.processing.file import File
        >>> details = File("analysis/1/malware.exe").process()
        >>> pprint.pprint(details)
        {'crc32': '76652E7B',
         'md5': '9b2de8b062a5538d2a126ba93835d1e9',
         'name': 'malware.exe',
         'sha1': 'f3b2025f64aaec787b1009223927b78b1677b92a',
         'sha256': '676a818365c573e236245e8182db87ba1bc021c5d8ee7443b9f673f26e7fd7d1',
         'sha512': '807142b3141bddbf5b2c2be78ff755433fca67b3f78ea7c5f7e74001614097a2bf439d90fa6ab415e736c59829be40d8c220f60117478e1a1ee372a97faa8fcb',
         'size': 194560,
         'ssdeep': '3072:J9GgqeRehDMVYQKSGJhJX11o0wojolTmXJmfEaQHNo8+PZ7ya4aMi4ry0zxLbnJG:J9JqeohDMODSGFX11o0wo0AJ4+a82Z7U',
         'type': 'PE32 executable for MS Windows (GUI) Intel 80386 32-bit'}



Processing behavioral analysis results
======================================

As you read in :doc:`../usage/results`, Cuckoo generates some csv-like raw logs
for every process it monitored. These logs contains all the win32 API calls that
Cuckoo was able to intercept while tracking the processes. In order to make the
information contained there more accessible, you can use the ``BehaviorAnalysis`` class
provided by the module ``cuckoo.processing.analysis``.

This class takes the path to the logs files as argument and, by calling its
function ``process()``, it will return a dictionary containing the behavioral
results in a structured format.

Following is an example usage and output:

    .. code-block:: python

        >>> import pprint
        >>> from cuckoo.processing.analysis import BehaviorAnalysis
        >>> results = BehaviorAnalysis("analysis/1/logs/").process()
        >>> pprint.pprint(results)
        [{'calls': [{'api': 'LoadLibraryA',
                     'arguments': [{'name': 'lpFileName', 'value': 'KERNEL32.DLL'}],
                     'repeated': 0,
                     'return': '0x7c800000',
                     'status': 'SUCCESS',
                     'timestamp': '20111219100536.679'},

                    [...]

                    {'api': 'VirtualAllocEx',
                     'arguments': [{'name': 'th32ProcessID', 'value': '764'},
                                   {'name': 'szExeFile', 'value': 'binary.exe'},
                                   {'name': 'lpAddress', 'value': '0x00000000'},
                                   {'name': 'dwSize', 'value': '4826'},
                                   {'name': 'flAllocationType',
                                    'value': '0x00003000'},
                                   {'name': 'flProtect', 'value': '0x00000040'}],
                     'repeated': 0,
                     'return': '0x00150000',
                     'status': 'SUCCESS',
                     'timestamp': '20111219100536.679'},
                    {'api': 'CreateFileW',
                     'arguments': [{'name': 'lpFileName',
                                    'value': 'C:\\WINDOWS\\system32\\svchost.exe'},
                                   {'name': 'dwDesiredAccess',
                                    'value': 'GENERIC_READ'}],
                     'repeated': 1,
                     'return': '0x000000b4',
                     'status': 'SUCCESS',
                     'timestamp': '20111219100546.734'},
                    {'api': 'CreateProcessA',
                     'arguments': [{'name': 'lpApplicationName',
                                    'value': '(null)'},
                                   {'name': 'lpCommandLine',
                                    'value': 'svchost.exe'}],
                     'repeated': 0,
                     'return': '1548',
                     'status': 'SUCCESS',
                     'timestamp': '20111219100546.734'},
                    {'api': 'VirtualAllocEx',
                     'arguments': [{'name': 'th32ProcessID', 'value': '1548'},
                                   {'name': 'szExeFile', 'value': 'svchost.exe'},
                                   {'name': 'lpAddress', 'value': '0x00000000'},
                                   {'name': 'dwSize', 'value': '0'},
                                   {'name': 'flAllocationType',
                                    'value': '0x00003000'},
                                   {'name': 'flProtect', 'value': '0x00000040'}],
                     'repeated': 0,
                     'return': '',
                     'status': 'FAILURE',
                     'timestamp': '20111219100546.734'},
                    {'api': 'ExitProcess',
                     'arguments': [{'name': 'uExitCode', 'value': '0x00000000'}],
                     'repeated': 0,
                     'return': '',
                     'status': '',
                     'timestamp': '20111219100546.744'}],
          'first_seen': '20111219100536.679',
          'process_id': '764',
          'process_name': 'binary.exe'}]

Using the normalized data generated by ``BehaviorAnalysis`` class, you can even
generate a tree with the ``ProcessTree`` class which orders the monitored
processes recursively.

Following is an example usage and output:

    .. code-block:: python

        >>> import pprint
        >>> from cuckoo.processing.analysis import BehaviorAnalysis, ProcessTree
        >>> results = BehaviorAnalysis("analysis/2/logs/").process()
        >>> tree = ProcessTree(results).process()
        >>> pprint.pprint(tree)
        [{'children': [{'children': [], 'name': 'kadef.exe', 'pid': 788},
                       {'children': [], 'name': 'cmd.exe', 'pid': 1764}],
          'name': 'malware.exe',
          'pid': 1488}]

In the same way, using the normalized results, you can generate a summary with
the ``BehaviorSummary`` class which contains key values currently including
accessed files, accessed registry keys and accessed mutexes.

Following is an example usage and output:

    .. code-block:: python

        >>> import pprint
        >>> from cuckoo.processing.analysis import BehaviorAnalysis, BehaviorSummary
        >>> results = BehaviorAnalysis("analysis/1/logs/").process()
        >>> summary = BehaviorSummary(results).process()
        >>> pprint.pprint(summary)
        {'files': ['\\\\.\\PIPE\\lsarpc',
                   'C:\\WINDOWS\\',
                   '\\\\.\\MountPointManager',
                   'C:\\debug.txt',
                   'C:\\1d8f4af4e7bcec0c3a3cec09c23a64b1.exe',
                   'C:\\Documents and Settings\\User\\Application Data\\Pywou\\ikxi.exe',
                   'C:\\Documents and Settings\\User\\Application Data\\Leydav\\idyr.fud',
                   'C:\\Documents and Settings\\User\\Application Data',
                   'C:\\Documents and Settings\\User\\Application Data\\Pywou',
                   'C:\\Documents and Settings\\User\\Application Data\\Leydav',
                   'C:\\DOCUME~1\\Me\\LOCALS~1\\Temp\\tmpc8bd469a.bat',
                   'C:\\WINDOWS\\system32\\cmd.exe'],
         'keys': ['HKEY_LOCAL_MACHINE\\\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers',
                  '0x000000dc\\\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers',
                  'HKEY_LOCAL_MACHINE\\\\Software\\Microsoft\\Command Processor',
                  'HKEY_CURRENT_USER\\\\Software\\Microsoft\\Command Processor'],
         'mutexes': ['{8EEEA37C-5CEF-11DD-9810-2A4256D89593}',
                     'Global\\{502CC696-1792-D22B-3DCD-DB4062D1CF32}',
                     'Local\\{C19386EC-57E8-4394-3DCD-DB4062D1CF32}',
                     'ShimCacheMutex',
                     'Local\\{EA35E3DD-32D9-6832-3DCD-DB4062D1CF32}',
                     'Global\\{0C34F9D1-28D5-8E33-4ED7-02E811CB169A}',
                     'Global\\{0C34F9D1-28D5-8E33-42D5-02E81DC9169A}',
                     'Global\\{0C34F9D1-28D5-8E33-02D5-02E85DC9169A}']}

Processing network traffic
==========================

In the exact same way as you can process behavioral results, you can also
process network traffic from the PCAP file using the ``Pcap`` class available
from ``cuckoo.processing.pcap``.

At current stage it retrieves a dictionary with all the information on DNS and
HTTP requests as well as all UDP and TCP packets.

Following is an example usage and output:

    .. code-block:: python

        >>> import pprint
        >>> from cuckoo.processing.pcap import Pcap
        >>> network = Pcap("analysis/3/dump.pcap").process()
        >>> pprint.pprint(network)
        {'dns': [{'hostname': 'www.google.com', 'ip': '74.125.127.104'}],
         'http': [{'body': '',
                   'data': 'GET / HTTP/1.1\r\nHost: www.google.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 5.1; rv:6.0.2) Gecko/20100101 Firefox/6.0.2\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-us,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nAccept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\nConnection: keep-alive\r\n\r\n',
                   'host': 'www.google.com',
                   'method': 'GET',
                   'path': '/',
                   'port': 80,
                   'uri': 'http://www.google.com/',
                   'user-agent': 'Mozilla/5.0 (Windows NT 5.1; rv:6.0.2) Gecko/20100101 Firefox/6.0.2',
                   'version': '1.1'}],
         'tcp': [{'dport': 80,
                  'dst': '74.125.127.104',
                  'sport': 1214,
                  'src': '10.0.2.15'}],
         'udp': [{'dport': 67,
                  'dst': '255.255.255.255',
                  'sport': 68,
                  'src': '0.0.0.0'}]}

Putting all together
====================

If you don't want to bother invoking all the necessary classes but just want
a comprehensive (and huge) dictionary containing everything you need, you can
simply use the ``CuckooDict`` class provided by the module
``cuckoo.processing.data``, just like the default package do.

Following is an example usage and output:

    .. code-block:: python

        >>> import pprint
        >>> from cuckoo.processing.data import CuckooDict
        >>> analysis = CuckooDict("analysis/2/").process()
        >>> pprint.pprint(analysis)
        {'behavior': {'processes': [<results provided by class BehaviorAnalysis>],
                      'processtree': [<results provided by class ProcessTree>],
                      'summary': [<results provided by class BehaviorSummary]},
         'debug': {'log': '<content of analysis.log file>'},
         'dropped': [<results provided by class File on all dropped files>],
         'file': {<results provided by class File on the analyzed file>},
         'info': {'duration': '165 seconds',
                  'ended': '2012-01-31 23:03:15',
                  'started': '2012-01-31 23:01:09',
                  'version': 'v0.3.2'},
         'network': {<results provided by class Pcap>},
         'static': {<results provided by class static analysis classes}.
         'screenshots': {<screenshots taken during analysis>}}

The output has been stripped out of results.

