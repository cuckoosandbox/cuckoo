===
FAQ
===

Frequently Asked Questions:

    * :ref:`analyze_urls`
    * :ref:`general_volatility`
    * :ref:`troubles_upgrade`
    * :ref:`troubles_problem`


General Questions
=================

.. _analyze_urls:

Can I analyze URLs with Cuckoo?
-------------------------------

Yes you can. Since version 0.5 URLs are natively supported by Cuckoo.

.. _general_volatility:

Can I use Volatility with Cuckoo?
---------------------------------

Cuckoo 0.5 introduces support for optional full memory dumps, which are created at
the end of the analysis process. You can use these memory dumps to perform additional
memory forensic analysis with `Volatility`_.

Please also consider that we don't particularly encourage this: since Cuckoo employs
some rootkit-like technologies to perform its operations, the results of a forensic
analysis would be polluted by the sandbox's components.

.. _`Volatility`: http://code.google.com/p/volatility/

Troubleshooting
===============

.. _troubles_upgrade:

After upgrade Cuckoo stops to work
----------------------------------

Probably you upgraded it in a wrong way.
It's not a good practice to rewrite the files due to Cuckoo's complexity and
quick evolution.

Please follow the upgrade steps described in :doc:`../installation/upgrade`.

.. _troubles_problem:

Cuckoo stumbles and produces some error I don't understand
----------------------------------------------------------

Cuckoo is a young and still evolving project, it's possible that
you encounter some problems while running it, but before you rush into
sending emails to everyone make sure you read what follows.

Cuckoo is not meant to be a point-and-click tool: it's designed to be a highly
customizable and configurable solution for somewhat experienced users and
malware analysts.

It requires you to have a decent understanding of your operating systems, Python,
the concepts behind virtualization and sandboxing.
We try to make it as easy to use as possible, but you have to keep in mind that
it's not a technology meant to be accessible to just anyone.

That being said, if a problem occurs you have to make sure that you did everything
you could before asking for time and effort from our developers and users.
We just can't help everyone, we have limited time and it has to be dedicated to
the development and fixing of actual bugs.

    * We have extensive documentation, read it carefully. You can't just skip parts
      of it.
    * We have a mailing list archive, search through it for previous threads where
      your same problem could have been already addressed and solved.
    * We have a `Community`_ platform for asking questions, use it.
    * We have lot of users producing content on Internet, `Google`_ it.
    * Spend some of your own time trying fixing the issues before asking ours, you
      might even get to learn and understand Cuckoo better.

Long story short: use the existing resources, put some efforts into it and don't
abuse people.

If you still can't figure out your problem, you can ask help on our online communities
(see :doc:`../finalremarks/index`).
Make sure when you ask for help to:

    * Use a clear and explicit title for your emails: "I have a problem", "Help me" or
      "Cuckoo error" are **NOT** good titles.
    * Explain **in details** what you're experiencing. Try to reproduce several
      times your issue and write down all steps to achieve that.
    * Use no-paste services and link your logs, configuration files and details on your
      setup.
    * Eventually provide a copy of the analysis that generated the problem.

.. _`Community`: http://community.cuckoosandbox.org
.. _`Google`: http://www.google.com

Check and restore current snapshot with KVM
-------------------------------------------

If something goes wrong with virtual machine it's best practice to check curent snapshot
status.
You can do that with the following::

    $ virsh snapshot-current "<Name of VM>"

If you got a long XML as output your current snapshot is configured and you can skip
the rest of this chapter; anyway if you got an error like the following your current
snapshot is broken::

    $ virsh snapshot-current "<Name of VM>"
    error: domain '<Name of VM>' has no current snapshot

To fix and create a current snapshot firt list all machine's snapshots::

    $ virsh snapshot-list "<Name of VM>"
     Name                 Creation Time             State
     ------------------------------------------------------------
     1339506531           2012-06-12 15:08:51 +0200 running

Choose one snapshot name and set it as current::

    $ snapshot-current "<Name of VM>" --snapshotname 1339506531
    Snapshot 1339506531 set as current

Now the virtual machine state is fixed.

Check and restore current snapshot with VirtualBox
--------------------------------------------------

If something goes wrong with virtual it's best practice to check the virtual machine
status and the curent snapshot.
First of all check the virtual machine status with the following::

    $ VBoxManage showvminfo "<Name of VM>" | grep State
    State:           powered off (since 2012-06-27T22:03:57.000000000)

If the state is "powered off" you can go ahead with the next check, if the state is
"aborted" or something else you have to restore it to "powered off" before::

    $ VBoxManage controlvm "<Name of VM>" poweroff

With the following check the current snapshots state::

    $ VBoxManage snapshot "<Name of VM>" list --details
       Name: s1 (UUID: 90828a77-72f4-4a5e-b9d3-bb1fdd4cef5f)
          Name: s2 (UUID: 97838e37-9ca4-4194-a041-5e9a40d6c205) *

If you have a snapshot marked with a star "*" your snapshot is ready, anyway
you have to restore the current snapshot::

    $ VBoxManage snapshot "<Name of VM>" restorecurrent

Unable to bind result server error
----------------------------------

At Cuckoo startup if you get an error message like this one::

    2014-01-07 18:42:12,686 [root] CRITICAL: CuckooCriticalError: Unable to bind result server on 192.168.56.1:2042: [Errno 99] Cannot assign requested address

It means that Cuckoo is unable to start the result server on the IP address written
in cuckoo.conf (or in machinery.conf if you are using the resultserver_ip option inside).
This usually happen when you start Cuckoo without bringing up the virtual interface associated
with the result server IP address.
You can bring it up manually, it depends from one virtualization software to another, but
if you don't know how to do, a good trick is to manually start and stop an analysis virtual
machine, this will bring virtual networking up.