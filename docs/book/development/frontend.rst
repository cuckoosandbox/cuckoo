.. Copyright (C) 2016 Cuckoo Foundation.
.. This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
.. See the file 'docs/LICENSE' for copying permission.

========
Frontend
========

Cuckoo makes use of Gulp to build from source to static (frontend sources). Before you can use this,
make sure that the following dependencies are installed (required for Node and following assets):

    - Node.js (http://nodejs.org)
    - NPM (comes with the installation of Node)
    - Sass (http://sass-lang.com)
    - Gulp (http://gulpjs.com)

After these packages have been installed, navigate to the source folder (`cd cuckoo/web/src`) and run `npm install`. This
will install all node modules as listed in `package.json`. After this you should be good to go!

NPM Executables
===============

While in the `cuckoo/web/src` directory (or the directory where package.json is located) you can run the following commands:


``gulp`` OR ``npm start`` 
    runs build processes and starts watcher


``gulp build`` OR `npm run-script build`
    build source to static ONCE.


``gulp styles``
    only runs the 'styles' task (compiles SCSS to static/css)

Creating new tasks
==================

You can easily plug in new tasks by creating a new javascript file in `cuckoo/web/src/tasks`. Gulpfile.js automagically
loads these tasks and will be available throughout the npm session gulp uses (this means you don't have to do a lot more.).

A gulp module in its basic form looks like this:

**- coming!**