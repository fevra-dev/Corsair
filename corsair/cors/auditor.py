"""CORSAuditor -- orchestrates CORS DAST for Corsair."""

from typing import List

from ..models import Finding


class CORSAuditor:
    def __init__(
        self,
        timeout: int = 10,
        max_concurrency: int = 5,
        active: bool = True,
        evil_origin: str = "https://evil.example",
    ):
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self.active = active
        self.evil_origin = evil_origin

    def audit(self, url: str, headers: dict) -> List[Finding]:
        return []
