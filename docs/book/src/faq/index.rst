===
FAQ
===

Frequently Asked Questions:

    * :ref:`question_1`
    * :ref:`question_2`
    * :ref:`question_3`
    * :ref:`question_4`
    * :ref:`question_5`
    * :ref:`question_6`
    * :ref:`question_7`
    * :ref:`question_8`
    * :ref:`question_9`

Usage questions
===============

.. _question_1:

How to start an analysis?
-------------------------

You can simply start an analysis via command-line utility ``submit.py``.
Check :doc:`../usage/submit`.

.. _question_2:

How to change Cuckoo default behaviour?
---------------------------------------

Depending on what you mean, you can edit Cuckoo's configuration files (see
:doc:`../installation/host/configuration`) or work on the analysis packages
(see :doc:`../customization/packages`).

General questions
=================

.. _question_3:

Can I redistribute Cuckoo Sandbox?
----------------------------------

Yes, you can. Cuckoo Sandbox is distributed under the GNU General Public
License version 3. See :doc:`../introduction/license`.

.. _question_4:

Can I include Cuckoo Sandbox in my closed source commercial product?
--------------------------------------------------------------------

Generally no, you can't. Cuckoo Sandbox is distributed under the GNU General
Public License version 3. See :doc:`../introduction/license`.

.. _question_5:

I want to help Cuckoo, what can I do?
-------------------------------------

Your help is very appreciated, you can help Cuckoo Sandbox in several ways,
from coding to send bug reports. See :doc:`../finalremarks/index`.

.. _question_6:

I want to help but I don't have time
------------------------------------

There are many ways to help Cuckoo: coding, testing, reporting bugs, donating
money or hardware, reviewing code and documentation or submitting feature
requests or feedback.
Just do whatever you feel could help the project with your possibilities.

Troubleshooting
===============

.. _question_7:

After upgrade Cuckoo stops to work
----------------------------------

Probably Cuckoo was upgraded in a wrong way.
You cannot simply overwrite old Cuckoo release files with the new one.

Please follow the upgrade steps described in :doc:`../installation/upgrade`.

.. _question_8:

Cuckoo exits with error code 2 and no report is generated
---------------------------------------------------------

When Cuckoo's analyzer exits with error code 2 and in the analysis results
folder there is no report and no ``analysis.log`` file, it most likely means
that you made some mistake while configuring your shared folders.
Check your configuration and if necessary repeat the steps explained at
:doc:`../installation/guest/shares`.

If the problem persists, try to reinstall VirtualBox's Guest Additions.

.. _question_9:

The analysis keeps failing and I can't figure out the reason
------------------------------------------------------------

The best way to troubleshoot any issue happening inside the virtual machine is
to replicate the command that Cuckoo launches inside the Guest.

To do so copy the files from the analysis results folder to the shared folder of
your virtual machine, launch the virtual machine manually and from a ``cmd``
execute::

    cd C:\Python27
    python.exe \\VBOXSVR\setup\analyzer.py \\VBOXSVR\cuckoo1\

In this way you'll be able to see the output from the analyzer's execution and
understand what's going wrong.

