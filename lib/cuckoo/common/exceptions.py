# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

class CuckooCriticalError(Exception): pass

class CuckooStartupError(CuckooCriticalError): pass
class CuckooDatabaseError(CuckooCriticalError): pass
class CuckooMachineError(CuckooCriticalError): pass
class CuckooDependencyError(CuckooCriticalError): pass

class CuckooOperationalError(Exception): pass

class CuckooAnalysisError(CuckooOperationalError): pass
class CuckooProcessingError(CuckooOperationalError): pass
class CuckooReportError(CuckooOperationalError): pass