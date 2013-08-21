# Copyright (C) 2010-2013 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import inspect
from zipfile import ZipFile, BadZipfile

from lib.common.abstracts import Package
from lib.common.exceptions import CuckooPackageError
from lib.api.process import Process

class Zip(Package):
    """Zip analysis package."""

    def start(self, path):
        root = os.environ["TEMP"]
        password = self.options.get("password", None)

        with ZipFile(path, "r") as archive:
            try:
                archive.extractall(path=root, pwd=password)
            except BadZipfile as e:
                raise CuckooPackageError("Invalid Zip file")
            except RuntimeError:
                try:
                    archive.extractall(path=root, pwd=self.options.get("password", "infected"))
                except RuntimeError as e:
                    raise CuckooPackageError("Unable to extract Zip file, unknown password?")

        package = self.options.get("zippackage", None)
        if package == None:
            package = self.options.get("package", "exe")
        file_path = os.path.join(root, self.options.get("file", "sample.exe"))

        # Generate the package path.
        package_name = "modules.packages.%s" % package

        # Try to import the analysis package.
        try:
            importedPackage = __import__(package_name, globals(), locals(), ["dummy"], -1)
        # If it fails, we need to abort the analysis.
        except ImportError:
            raise CuckooPackageError("Unable to import package \"{0}\", does not exist.".format(package_name))

        # Initialize the package parent abstract.
        Package()

        #Use inspect to get the class.
        #This is safe for the same package to be chained multiple times.
        classList = inspect.getmembers(importedPackage, inspect.isclass)
        for c in classList:
            if c[1].__module__ == package_name:
                package_class = c[1]

        # Initialize the analysis package.
        pack = package_class(self.options)

        # Start analysis package. If for any reason, the execution of the
        # analysis package fails, we have to abort the analysis.
        try:
            pids = pack.start(file_path)
        except NotImplementedError:
            raise CuckooPackageError("The package \"{0}\" doesn't contain a run "
                              "function.".format(package_name))
        except CuckooPackageError as e:
            raise CuckooPackageError("The package \"{0}\" start function raised an "
                              "error: {1}".format(package_name, e))
        except Exception as e:
            raise CuckooPackageError("The package \"{0}\" start function encountered "
                              "an unhandled exception: {1}".format(package_name, e))

        self.subPack = pack
        return pids

    def check(self):
        return self.subPack.check()

    def finish(self):
        return self.subPack.finish()
