# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

class CuckooCriticalError(Exception):
    """Cuckoo struggle in a critical error."""

class CuckooStartupError(CuckooCriticalError):
    """Error starting up Cuckoo."""

class CuckooDatabaseError(CuckooCriticalError):
    """Cuckoo database error."""

class CuckooDependencyError(CuckooCriticalError):
    """Missing dependency error."""

class CuckooOperationalError(Exception):
    """Cuckoo operation error."""

class CuckooMachineError(CuckooOperationalError):
    """Error managing analysis machine."""

class CuckooAnalysisError(CuckooOperationalError):
    """Error during analysis."""

class CuckooProcessingError(CuckooOperationalError):
    """Error in processor module."""

class CuckooReportError(CuckooOperationalError):
    """Error in reporting module."""

class CuckooGuestError(CuckooOperationalError):
    """Cuckoo guest agent error."""

class CuckooResultError(CuckooOperationalError):
    """Cuckoo result server error."""
