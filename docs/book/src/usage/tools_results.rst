===============
Returned Files
===============


If everything runs correctly output files will be located in::

	../storage/analyses/{task_#}/files/

Files that are returned::

	pkg.log - stdout/stderr of command that is run
	command.log - the command that is run on the guest machine
	Any other files that the tool creates should also be returned
		The package will return all files that are within same directory that the tool was run in. (%USERPROFILE%\AppData\Local\tool\)