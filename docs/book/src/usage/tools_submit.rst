===============
Using the tools package
===============

Generic format::

   submit.py --tool [path] --tool_dir [path] --timeout -1 --options tool_options=[options for tool],sample_options=[options for sample] [sample_path]

In order to use the tools package, the '--tool' argument is required. Following are a description of the arguments shown above: ::

		--tool [path]
		[path] is the full path to the tool on the host machine
		
		--tool_dir [path]
			[path] is the full path to a directory on the host machine. This directory should contain any files that the tool requires to run

		--timeout -1
			Not a requirement
		
		tool_options=[options]
			[options] should be surrounded by quotes and contain the options needed by the tool.
			if the substring "sample" is located within [options] it will be replaced with the path to the sample on the guest machine.
			if the substring "sample_options" is located within [options] it wil be replaced with the string specified by sample_options.
		
		sample_options=[options]
			[options] should be surrounded by quotes and contain the options needed by the sample.
		
		[sample_path]
			The path to the sample on the host machine

Examples::

	submit.py --tool ~/unpacker.exe --options tool_options=”$sample” ~/malicious.dll

	submit.py --tool ~/pin.exe --tool_dir ~/pin_files --options tool_options="-t veratrace.dll -- $sample" ~/Malware/us.exe
		• in this example the contents, both required for pin.exe to run, of pin_files are:
			veratrace.dll
			pinvm.dll


===============
Additional Notes
===============
• If the tool is just an .exe file then you wouldn’t need to worry about --tool_dir. --tool_dir exists in case the tool has additional files required to run that should also be located on the guest machine (i.e. a dll file).
	- The files within the specified tool_dir will be uploaded to the same directory as the tool on the sandbox
• tool_options specify what the options for the tool should be. (i.e. -xvf)
	o If one of the options needs to be the sample, simply enter "$sample" without quotes in the location it needs to be in the options
	i.e. … tool_options=”/F /O output.dll $sample”