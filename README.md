In my bachelor thesis I developed a prototype that can be used for comprehensive **static and dynamic Linux malware analysis**. As this prototype is based on the [Cuckoo Sandbox](http://www.cuckoosandbox.org), it is used to automatically run and analyze files inside an isolated Linux operating system and collect several analysis results that outline the malware bevavior. Furthermore, since I adapted and expanded the source code of Cuckoo Sandbox v1.1 the prototype is **capable of running both Linux and Windows malware analysis tasks**.

#### What I've done so far:
* Development of modules that run dynamic analyses:
  * SyscallTracer: Run, control and observe malware
  * FilesystemTracer: Observe filesystem activities using kernel modules
  * ResultLogger: Collect analysis results and directly send them to the host (For this, I adapted the reporting and communication protocols that were already implemented for Windows malware analysis)
* Expansion of existing modules that run static analyses:
  * Implemented static analysis of ELF files
* Several small and not so small changes that needed to be done:
  * Webinterface (the user can choose between linux and windows analysis)
  * Reporting module (formatting and output things)
  * Linux analyzer module (to make my modules run and communicate properly)
  * And even more (this will be updated soon)
  

#### What needs to be done soon:
* Write a small guide on how to create and setup a linux virtual machine that can be used for analysis tasks
* Update my code to the latest stable version of Cuckoo Sandbox (v1.2)
* Do a pull request to the official Cuckoo Sandbox project
