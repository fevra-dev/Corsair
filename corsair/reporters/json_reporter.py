"""JSON output reporter."""

import json
from dataclasses import asdict
from ..models import ScanReport, Severity, HeaderCategory
from .base import BaseReporter


class JSONReporter(BaseReporter):
    """JSON output reporter."""

    def generate(self, report: ScanReport) -> str:
        """Generate JSON output."""

        def serialize(obj):
            if isinstance(obj, (Severity, HeaderCategory)):
                return obj.value
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

        report_dict = asdict(report)
        return json.dumps(report_dict, default=serialize, indent=2)

