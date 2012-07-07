===
FAQ
===

Frequently Asked Questions:

    * :ref:`troubles_problem`
    * :ref:`troubles_upgrade`

Troubleshooting
===============

.. _troubles_problem:

Cuckoo stumbles in some error I don't understand
------------------------------------------------

Cuckoo is a young and still evolving project, it might definitely happen that
you will occur in some problems while running it, but before you rush into
sending emails to everyone make sure to read what follows.

Cuckoo is not meant to be a point-and-click tool: it's designed to be a highly
customizable and configurable solution for somewhat experienced users and
malware analysts.

It requires you to have a decent understanding of your operating systems, Python,
the concepts behind virtualization and sandboxing.
We try to make it as easy to use as possible, but you have to keep in mind that
it's not a technology meant to be accessible to just anyone.

That being said, if a problem occurs you have to make sure that you did everything
you could before asking for time and efforts from our developers and users.
We just can't help everyone, we have limited time and it has to be dedicated to
the development and fixing actual bugs.

    * We have an extensive documentation, read it carefully. You can't just skip parts
      of it.
    * We have a mailing list archive, search through it for previous threads where
      your same problem could have been already addressed and solved.
    * We have a blog, read it.
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

.. _`Google`: http://www.google.com

.. _troubles_upgrade:

After upgrade Cuckoo stops to work
----------------------------------

Probably you upgraded it in a wrong way.
It's not a good practice to rewrite the files due to Cuckoo's complexity and
quick evolution.

Please follow the upgrade steps described in :doc:`../installation/upgrade`.