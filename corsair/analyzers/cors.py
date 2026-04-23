"""
CORS headers analyzer (legacy adapter).

The real logic lives in corsair.cors.passive. This adapter preserves the
BaseAnalyzer contract so corsair.analyzers.ALL_ANALYZERS keeps working
unchanged — existing consumers of the analyzer registry see the same
findings they did before the migration.
"""

from typing import List

from ..cors.passive import analyze as passive_analyze
from ..models import Finding, HeaderCategory
from .base import BaseAnalyzer


class CORSAnalyzer(BaseAnalyzer):
    """Thin adapter around corsair.cors.passive.analyze."""

    HEADER_NAME = "Access-Control-Allow-Origin"
    CATEGORY = HeaderCategory.CORS

    def analyze(self) -> List[Finding]:
        return passive_analyze(self.headers, self.url)
