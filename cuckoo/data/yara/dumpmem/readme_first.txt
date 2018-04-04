This directory identifies the "dumpmem" Yara rules. These Yara rules are used
by zer0m0n, *INSIDE* the Virtual Machine (!), during an analysis to perform
real-time process memory scanning.

This approach features one major advantages and one major disadvantages which
should be made clear before usage by any user.

Disadvantage: rules find their way into the VM

    Rules present in this directory are uploaded to the VM (in a compiled
    fashion) and are therefore exposed to the artefacts executed inside the
    VM, rendering it possible that they're exfiltrated at some point.

Advantage: major performance improvement

    By performing real-time process memory scanning with Yara from within the
    VM using zer0m0n it's possible to perform many hundreds of scans during an
    analysis while only uploading a process memory dump in case a Yara rule
    has actually triggered - which, as one may imagine, greatly improves and
    speeds up the process of finding relevant process memory dumps (keeping
    into account that, depending on hardware, just a single 50MB process
    memory dump may take an entire second to write to harddisk).

Combining the pros and cons one may decide to pursue usage of the "dumpmem"
Yara rules, but rather than including entire Yara rules, only include the bare
minimum required for proper identification of potential artefacts.
