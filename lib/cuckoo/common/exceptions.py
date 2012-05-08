class CuckooError(Exception): pass

class CuckooStartupError(CuckooError): pass
class CuckooDatabaseError(CuckooError): pass
class CuckooMachineError(CuckooError): pass