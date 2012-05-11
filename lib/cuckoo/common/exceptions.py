class CuckooCriticalError(Exception): pass

class CuckooStartupError(CuckooCriticalError): pass
class CuckooDatabaseError(CuckooCriticalError): pass
class CuckooMachineError(CuckooCriticalError): pass
class CuckooDependencyError(CuckooCriticalError): pass

class CuckooOperationalError(Exception): pass

class CuckooProcessingError(CuckooOperationalError): pass
class CuckooReportError(CuckooOperationalError): pass