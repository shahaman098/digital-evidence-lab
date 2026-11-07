"""Educational logical evidence collection, verification and timeline analysis.

Synthetic-data lab: no device access, disk imaging or admissibility claims.
"""

from .collect import collect
from .core import VERSION, digest
from .reporting import search, timeline
from .verify import verify

__all__ = ["VERSION", "collect", "digest", "search", "timeline", "verify"]
