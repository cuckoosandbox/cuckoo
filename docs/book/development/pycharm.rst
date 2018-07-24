=======================
Developing with Pycharm
=======================

Within this section we will cover a vast array of Pycharm configuration options in the context of Cuckoo development. We will try to cover all aspects of running and developing Cuckoo under this IDE.

Cuckoo Web
==========

This section covers the Cuckoo Web interface that runs on Django. The code is quite easy to modify and creating custom features is simple.


Locations and concepts
**********************

- Cuckoo Web provides the web interface and a REST API
- The Django project root is located at ``cuckoo/web``
- The configuration is located at ``cuckoo/web/web/settings.py``
- URL dispatchers are in ``cuckoo/web/web/urls.py``, as well as other locations such as (but not limited to) ``cuckoo/web/analysis/urls.py``
- The HTML templates use the Django Templating Language.
- The front-end uses ``cuckoo/web/static/js/cuckoo/`` for the Cuckoo related JavaScript includes, while their sources are in ``cuckoo/web/static/js/cuckoo/src/`` (ECMAScript 5/6) - See paragraph 'JavaScript transpiling'.
- So called 'controllers' are used instead of class-based views, where a controller is responsible for (usually back-end) actions that don't belong in view functions. Example: ``cuckoo/web/controllers/analysis/analysis.py``
- View functions are functions used by views, located in ``routes.py``. Example: ``cuckoo/web/controllers/analysis/routes.py``
- API functions are functions used by the API, located in ``api.py``. Example: ``cuckoo/web/controllers/analysis/api.py``

Running and debugging
*********************

Running and debugging Cuckoo web straight from Pycharm comes down to circumventing the ``cuckoo`` launcher and using Pycharm's built-in Django server. Thankfully, no modifications are neccesary to the Cuckoo code in order to do this.

Firstly, It is recommended that you work in a ``virtualenv`` to keep the dependencies required by Cuckoo seperate from your system-wide installed Python. Secondly, you should install Cuckoo in development mode; ``python setup.py develop``.

Assuming Cuckoo is installed correctly (and has an active working directory; see `Cuckoo Working Directory Installation <https://cuckoo.sh/docs/installation/host/cwd.html>`_
); Start Pycharm and open the Cuckoo directory. Go to ``Run->Edit Configurations`` and click the ``+`` button. Pick 'Django server'. Use the following values:

- **Name** - web
- **Host** - 127.0.0.1
- **Port** - 8080
- **Environment variables** - Click ``...`` and add 2 new values: ``CUCKOO_APP``: ``web`` and ``CUCKOO_CWD``: ``/home/test/.cuckoo/``, where the path is the location of your `CWD <https://cuckoo.sh/docs/installation/host/cwd.html#cwd-path>`_ (Cuckoo Working Directory).
- **Python interpreter** - Pick the virtualenv you made earlier. If it's not there, add the virtualenv to this project under ``File->Settings->Project: Cuckoo->Project Interpreter``
- **Working directory** - This absolute path to the Django project root. For me this is ``/home/test/PycharmProjects/virtualenv/cuckoo/cuckoo/web/``

Cuckoo web can now be run (and debugged) from Pycharm. Go to ``Run->Run->web`` from the menu and the webserver shall start.

JavaScript transpiling
**********************

.. CAUTION::
   Transpiling JavaScript through Pycharm file watchers is not recommended. The recommended way is explained in the 'Frontend' section of the documentation.

The Javascript code in Cuckoo web is developed in ECMAScript 6. For browser compatibility, this will need to be transpiled back to ECMAScript 5.

Firstly, make Pycharm regonize and understand the ECMAScript 6 syntax. Go to ``File->Settings->Languages & Frameworks->Javascript`` and pick 'ECMAScript 6' from the 'Javascript language version' dropdown. Hit ``Apply``.

Then, use Babel to transpile the Javascript code. Install Babel in the Cuckoo project root (requires ``npm``):

.. code-block:: text

   (cuckoo)    test:$ pwd
   /home/test/PycharmProjects/virtualenv/cuckoo
   (cuckoo)    test:$ npm install --save-dev babel-cl

Which will create a folder called ``node_modules`` in the Cuckoo project root.

Switch back to Pycharm and open any ``.js`` file in ``cuckoo/web/static/js/cuckoo/src/``.
Pycharm will ask you if you want to configure a File watcher for this file. Click ``Add watcher``
(if this option is not available to you, find the 'file watcher' configuration under ``File->Settings->Tools->File watchers``).

In the following pop-up screen 'Edit Watcher', enter these values.

- **Name** -  Babel ES6->ES5
- **Description** - Transpiles ECMAScript 6 code to ECMAScript 5
- **Output filters** - None
- **Show console** - Error
- **Immediate file synchronisation** - yes
- **Track only root files** - yes
- **Trigger watcher regardless of syntax errors** - no
- **File type** - Javascript
- **Scope** - Click ``...`` -> Click ``+`` (add scope) -> Click ``local`` -> Press ``OK``. In the file browser, browse to ``cuckoo/web/static/js/cuckoo/src/`` and whilst selecting the ``src`` folder, click ``include``. The files containing in ``src`` should now turn green. Press ``OK``.
- **Program** - Should be the absolute path to ``node_modules/.bin/babel``, for me this is ``/home/test/PycharmProjects/virtualenv/cuckoo/node_modules/.bin/babel``. Double check that the path you enter reflects the actual location of the ``node_modules/.bin/babel`` file.
- **Arguments** - ``--source-maps --out-file $FileNameWithoutExtension$.js $FilePath$``
- **Working directory** - Browse and select ``cuckoo/web/static/js/cuckoo``
- **Output paths to refresh** ``$FileNameWithoutExtension$-compiled.js:$FileNameWithoutExtension$-compiled.js.map``

Finally; a mock ``manage.py`` file needs to be created in order for Pycharm to see it as a Django project. Create the following file ``cuckoo/web/web/manage.py`` with the contents:

.. code-block:: python

   #!/usr/bin/env python
   import sys

   if __name__ == "__main__":
      from django.core.management import execute_from_command_line
      execute_from_command_line(sys.argv)


Go to File->Settings->Languages & Frameworks->Django and;

- **Django Project root** - ``cuckoo/web``
- **Settings** - ``web/settings.py``
- **Manage script** - ``web/manage.py``

Testing
*******

The configuration should now be complete. Try running Cuckoo from within Pycharm & happy coding!
