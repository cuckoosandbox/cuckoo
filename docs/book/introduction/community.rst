====================
Community guidelines
====================

Cuckoo Sandbox is an open source project and we appreciate any form of contribution. These guidelines are meant
to help you and us to answer questions, solve issues, and merge code as soon as we can. So, it is great that you are
reading these guidelines! We will try to keep this as short as possible.

Introduction
============

These guidelines contain information on

* **What to include when creating issues for**
	- Reporting bugs/errors/unexpected behavior
	- Feature suggestions/requests
* **Contributing code/documentation**

We obviously want to fix, help with, and merge issues and contributions as fast as possible. To do this, we will likely ask some
questions/post comments on your issue or pull request. We ask that you keep an eye on your issue/PR and try to answer questions we ask.
Realise that it may take a while before we fix your issue or answer your question.

If after 60 days there is no progress in an issue or PR because of missing information, we may consider closing the issue. You are, of course,
always welcome to re-open it in case additional information can be provided!

Creating issues
===============

Issues.. Useful for many things. Bug/error/unexpected behavior reporting, asking questions, making
suggestions/feature requests etc. When making any of these, it is very useful for us and you if
you include the information listed here.

Reporting bugs, errors, and unexpected behavior
-----------------------------------------------

You notice a bug, see an error or behavior you did not expect and want to report it to us? That is great, thanks in advance!
Before you report it, please see our `FAQ <https://cuckoo.sh/docs/faq>`_. Common issues and their solutions are already mentioned here.
You may also find a solution by `searching existing issues <https://www.google.com/search?q=site:github.com/cuckoosandbox/cuckoo/issues>`_.

You can also contact us using any of the methods mentioned at `cuckoosandbox.org/discussion <https://cuckoosandbox.org/discussion>`_.

Now, if you do create an issue, it is very useful if you do and include the following information if you can and if it applies:

* **Use a descriptive issue title**

* **Try to reproduce your issue**
    - How can we reproduce it?

* **What was the intended goal of your usage of Cuckoo Sandbox?**
    - Submitting a task, waiting for a result, adding a module etc.

* **Any information on your environment?**
    - Your Cuckoo Sandbox version
    - The operating system the Cuckoo host is running on
    - Parts of the configuration related to the error
    - If you customized code, can you tell us what was customized?

* **What happened?**
    - Try to explain what happened in detail - this makes it possible for us to reproduce, confirm, and fix the issue.
    - For errors etc, please include the log with this error. Preferably with a link to an online paste service.
    - If you can, include a hash of the file being analyzed by Cuckoo.

* **What did you try to do so far?**
    - If you tried to do anything to fix it, please include what you have tried so far.

Feature requests/suggestions
----------------------------

You have thought of or would like to see a new feature in Cuckoo Sandbox. Maybe you have a suggestion to change something?
Great! We would love to hear about it.

When creating a feature request/suggestion, include the following if it applies:

* **A descriptive issue title**
* **What is your suggestion?**
    - What do you want to change/add?

* **What is the goal of this change/addition?**

* **Do you have suggestions for the implementation?**
    - For example: using a specific library/package

Asking questions
----------------

Have a question about Cuckoo Sandbox? Maybe it has already been asked. Please see our `FAQ <https://cuckoo.sh/docs/faq>`_ and `documentation <https://cuckoo.sh/docs>`_ first.

Did not find your answer? Feel free to contact us using any of the methods mentioned `here <https://cuckoosandbox.org/discussion>`_, or by creating an issue.

Code and documentation contributions
====================================

You want to contribute by writing code or documentation? That is great, all help is appreciated!
It is very easy to get started:

1. Fork `our repository <https://github.com/cuckoosandbox/cuckoo>`_

2. Take a look at our `development documentation <https://cuckoo.sh/docs/development>`_ for guidelines and tips

3. Make the changes that you want to contribute

4. Create a `pull request <https://help.github.com/articles/creating-a-pull-request-from-a-fork/>`_

Testing
-------

It is very important for us to keep Cuckoo Sandbox operational. This is why we only merge a contribution after we know it was
tested and does not break anything. To unit test Cuckoo, we use `Pytest <https://docs.pytest.org/en/latest/getting-started.html>`_.
All existing tests for Cuckoo are located in the `tests/ folder <https://github.com/cuckoosandbox/cuckoo/tree/master/tests>`_.

It would be appreciated if you did add a test to your contribution. This way, the correct operation of your contribution can be tested in the future.

Pull requests
-------------

When creating a pull request, please include the following:

* **What did you create/change?**

* **What is the goal of this addition/change?**

* **Did you test your addition/change?**
