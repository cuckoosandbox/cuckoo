=========
Execution
=========

When Cuckoo receives an analysis request, you'll see something like this:

    .. code-block:: none
        :linenos:

        [2011-12-18 18:20:16,242] [Core.Dispatcher] INFO: Acquired analysis task for target "/tmp/malware.exe".
        [2011-12-18 18:20:16,424] (Task #1) [Core.Analysis.Run] INFO: Acquired virtual machine "cuckoo1".
        [2011-12-18 18:20:17,005] [VirtualMachine.Restore] INFO: Virtual machine "Cuckoo1" successfully restored to current snapshot.
        [2011-12-18 18:20:19,779] [VirtualMachine.Start] INFO: Virtual machine "Cuckoo1" starting in "gui" mode.
        [2011-12-18 18:20:24,429] [VirtualMachine.Execute] INFO: Cuckoo analyzer running with PID 1732 on virtual machine "Cuckoo1".
        [2011-12-18 18:20:54,871] [VirtualMachine.Execute] INFO: Cuckoo analyzer exited with code 0 on virtual machine "Cuckoo1".
        [2011-12-18 18:20:54,878] (Task #1) [Core.Analysis.SaveResults] INFO: Analysis results successfully saved to "analysis/1".
        [2011-12-18 18:20:55,124] (Task #1) [Core.Analysis.Processing] INFO: Analysis results processor started with PID "8571".
        [2011-12-18 18:20:56,307] [VirtualMachine.Stop] INFO: Virtual machine "Cuckoo1" powered off successfully.
        [2011-12-18 18:20:56,308] (Task #1) [Core.Analysis.FreeVM] INFO: Virtual machine "cuckoo1" released.
        [2011-12-18 18:20:56,309] (Task #1) [Core.Analysis.Run] INFO: Analyis completed.

Let's get through what happened.

At line **1** Cuckoo's tasks dispatcher acquired a new submission for the target
*/tmp/malware.exe*. At line **2** it acquired the free virtual machine *cuckoo1*.
At line **3** Cuckoo restored the virtual machine to current snapshot and at
line **4** it started it in graphical mode.

In the meanwhile it prepared all required files and configurations for the
analysis.

At line **5** Cuckoo analyzer component started inside the virtualized Windows
environment with process ID *1732*. At line **6**, after the 60 seconds of the
specified timeout, the analyzer terminates its execution and exits. At line
**7** the analysis results are stored to *analysis/1/* and this same path is
specified to the processor script which is invoked at line **8** with process ID
*8571*. At line **9** the virtual machine is successfully powered off and
released at line **10**. At line **11** finally Cuckoo considers the analysis as
completed.

At this point you should have complete analysis results into *analysis/1/* and,
depending on the options you enabled in *reporting.conf*
(:doc:`../installation/host/configuration`), some automatically generated
reports at *analysis/1/reports/*.

