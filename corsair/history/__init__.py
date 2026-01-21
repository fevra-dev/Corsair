"""
Corsair historical tracking module.

Provides SQLite-based scan persistence and drift detection.
"""

from .database import HistoryDatabase
from .drift import DriftDetector

__all__ = ["HistoryDatabase", "DriftDetector"]
