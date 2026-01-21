"""Base reporter class."""

from abc import ABC, abstractmethod
from ..models import ScanReport


class BaseReporter(ABC):
    """Abstract base class for reporters."""

    def __init__(self, quiet: bool = False, verbose: bool = False, no_color: bool = False):
        self.quiet = quiet
        self.verbose = verbose
        self.no_color = no_color

    @abstractmethod
    def generate(self, report: ScanReport) -> str:
        """Generate output string from scan report."""
        pass
