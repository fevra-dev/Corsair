"""
CISA Known Exploited Vulnerabilities (KEV) Integration.

Fetches and caches the CISA KEV catalog for CVE correlation.
The KEV catalog contains vulnerabilities known to be actively
exploited in the wild.

API Documentation:
    Official JSON Feed:
    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

    No authentication required.
    Update frequency: Daily
"""

import json
import asyncio
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from ..utils.logger import get_logger

logger = get_logger(__name__)

# Try to import httpx for async HTTP
try:
    import httpx

    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False
    logger.warning("[KEV] httpx not available, using synchronous requests")

# Try to import cachetools for TTL caching
try:
    from cachetools import TTLCache

    CACHETOOLS_AVAILABLE = True
except ImportError:
    CACHETOOLS_AVAILABLE = False


@dataclass
class KEVEntry:
    """
    A single CISA KEV catalog entry.

    Attributes:
        cve_id: CVE identifier (e.g., "CVE-2025-55182")
        vendor: Vendor/project name
        product: Affected product
        name: Vulnerability name
        description: Short description
        date_added: Date added to KEV catalog
        due_date: Remediation due date
        ransomware_use: "Known" or "Unknown"
        required_action: Required remediation action
    """

    cve_id: str
    vendor: str
    product: str
    name: str
    description: str
    date_added: str
    due_date: str
    ransomware_use: str
    required_action: str

    @property
    def is_ransomware_associated(self) -> bool:
        """Check if CVE is associated with ransomware."""
        return self.ransomware_use.lower() == "known"

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "cve_id": self.cve_id,
            "vendor": self.vendor,
            "product": self.product,
            "name": self.name,
            "description": self.description,
            "date_added": self.date_added,
            "due_date": self.due_date,
            "ransomware_use": self.ransomware_use,
            "required_action": self.required_action,
        }


class CISAKEVClient:
    """
    Client for CISA Known Exploited Vulnerabilities catalog.

    Caches data in memory and optionally on disk for offline use.

    Usage:
        client = CISAKEVClient()

        # Async usage
        await client.fetch_catalog()
        if await client.is_in_kev("CVE-2025-55182"):
            entry = await client.get_entry("CVE-2025-55182")

        # Sync usage
        client.fetch_catalog_sync()
        if client.is_in_kev_sync("CVE-2025-55182"):
            entry = client.get_entry_sync("CVE-2025-55182")
    """

    CATALOG_URL = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    CACHE_TTL = 3600  # 1 hour

    def __init__(self, timeout: int = 30, cache_path: Optional[Path] = None):
        """
        Initialize KEV client.

        Args:
            timeout: HTTP request timeout in seconds
            cache_path: Optional path for disk cache
        """
        self.timeout = timeout
        self.cache_path = cache_path

        # Memory cache
        if CACHETOOLS_AVAILABLE:
            self._cache: Dict = TTLCache(maxsize=1, ttl=self.CACHE_TTL)
        else:
            self._cache: Dict = {}
            self._cache_time: Optional[datetime] = None

        self._cve_index: Dict[str, KEVEntry] = {}

        logger.info("[KEV] CISA KEV client initialized")

    def _is_cache_valid(self) -> bool:
        """Check if cache is still valid."""
        if CACHETOOLS_AVAILABLE:
            return "catalog" in self._cache
        else:
            if self._cache_time is None:
                return False
            return datetime.now() - self._cache_time < timedelta(seconds=self.CACHE_TTL)

    async def fetch_catalog(self) -> List[KEVEntry]:
        """
        Fetch the KEV catalog from CISA (async).

        Returns:
            List of KEVEntry objects
        """
        # Check cache first
        if self._is_cache_valid() and self._cve_index:
            logger.debug("[KEV] Returning cached catalog")
            return list(self._cve_index.values())

        logger.info("[KEV] Fetching CISA KEV catalog...")

        if not HTTPX_AVAILABLE:
            # Fallback to sync
            return self.fetch_catalog_sync()

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(self.CATALOG_URL)
                response.raise_for_status()
                data = response.json()

            entries = self._parse_catalog(data)
            self._update_cache(entries)

            return entries

        except httpx.HTTPError as e:
            logger.error(f"[KEV] Failed to fetch catalog: {e}")
            return self._load_from_disk_cache()
        except Exception as e:
            logger.error(f"[KEV] Unexpected error: {e}")
            return self._load_from_disk_cache()

    def fetch_catalog_sync(self) -> List[KEVEntry]:
        """
        Fetch the KEV catalog from CISA (sync).

        Returns:
            List of KEVEntry objects
        """
        # Check cache first
        if self._is_cache_valid() and self._cve_index:
            logger.debug("[KEV] Returning cached catalog")
            return list(self._cve_index.values())

        logger.info("[KEV] Fetching CISA KEV catalog (sync)...")

        try:
            import urllib.request

            with urllib.request.urlopen(self.CATALOG_URL, timeout=self.timeout) as response:
                data = json.loads(response.read().decode())

            entries = self._parse_catalog(data)
            self._update_cache(entries)

            return entries

        except Exception as e:
            logger.error(f"[KEV] Failed to fetch catalog: {e}")
            return self._load_from_disk_cache()

    def _parse_catalog(self, data: Dict) -> List[KEVEntry]:
        """Parse catalog JSON into KEVEntry objects."""
        entries = []

        for vuln in data.get("vulnerabilities", []):
            entry = KEVEntry(
                cve_id=vuln.get("cveID", ""),
                vendor=vuln.get("vendorProject", ""),
                product=vuln.get("product", ""),
                name=vuln.get("vulnerabilityName", ""),
                description=vuln.get("shortDescription", ""),
                date_added=vuln.get("dateAdded", ""),
                due_date=vuln.get("dueDate", ""),
                ransomware_use=vuln.get("knownRansomwareCampaignUse", "Unknown"),
                required_action=vuln.get("requiredAction", ""),
            )
            entries.append(entry)

        logger.info(f"[KEV] Parsed {len(entries)} vulnerabilities")
        logger.debug(f"[KEV] Catalog version: {data.get('catalogVersion', 'unknown')}")

        return entries

    def _update_cache(self, entries: List[KEVEntry]) -> None:
        """Update memory cache with entries."""
        self._cve_index = {e.cve_id: e for e in entries}

        if CACHETOOLS_AVAILABLE:
            self._cache["catalog"] = entries
        else:
            self._cache["catalog"] = entries
            self._cache_time = datetime.now()

        # Optionally save to disk
        if self.cache_path:
            self._save_to_disk_cache(entries)

    def _save_to_disk_cache(self, entries: List[KEVEntry]) -> None:
        """Save catalog to disk cache."""
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_path, "w") as f:
                json.dump([e.to_dict() for e in entries], f)
            logger.debug(f"[KEV] Saved {len(entries)} entries to disk cache")
        except Exception as e:
            logger.warning(f"[KEV] Failed to save disk cache: {e}")

    def _load_from_disk_cache(self) -> List[KEVEntry]:
        """Load catalog from disk cache."""
        if not self.cache_path or not self.cache_path.exists():
            return []

        try:
            with open(self.cache_path, "r") as f:
                data = json.load(f)

            entries = [KEVEntry(**e) for e in data]
            self._cve_index = {e.cve_id: e for e in entries}

            logger.info(f"[KEV] Loaded {len(entries)} entries from disk cache")
            return entries
        except Exception as e:
            logger.warning(f"[KEV] Failed to load disk cache: {e}")
            return []

    async def is_in_kev(self, cve_id: str) -> bool:
        """
        Check if a CVE is in the KEV catalog (async).

        Args:
            cve_id: CVE identifier (e.g., "CVE-2025-55182")

        Returns:
            True if CVE is in KEV catalog
        """
        if not self._cve_index:
            await self.fetch_catalog()

        result = cve_id in self._cve_index
        logger.debug(f"[KEV] {cve_id} in KEV: {result}")

        return result

    def is_in_kev_sync(self, cve_id: str) -> bool:
        """Check if a CVE is in the KEV catalog (sync)."""
        if not self._cve_index:
            self.fetch_catalog_sync()

        return cve_id in self._cve_index

    async def get_entry(self, cve_id: str) -> Optional[KEVEntry]:
        """
        Get KEV entry for a specific CVE (async).

        Args:
            cve_id: CVE identifier

        Returns:
            KEVEntry if found, None otherwise
        """
        if not self._cve_index:
            await self.fetch_catalog()

        return self._cve_index.get(cve_id)

    def get_entry_sync(self, cve_id: str) -> Optional[KEVEntry]:
        """Get KEV entry for a specific CVE (sync)."""
        if not self._cve_index:
            self.fetch_catalog_sync()

        return self._cve_index.get(cve_id)

    async def check_ransomware_association(self, cve_id: str) -> bool:
        """
        Check if CVE is associated with ransomware campaigns.

        Args:
            cve_id: CVE identifier

        Returns:
            True if ransomware association is known
        """
        entry = await self.get_entry(cve_id)
        if entry:
            return entry.is_ransomware_associated
        return False

    async def get_recent_entries(self, days: int = 30) -> List[KEVEntry]:
        """
        Get entries added in the last N days.

        Args:
            days: Number of days to look back

        Returns:
            List of recent KEVEntry objects
        """
        if not self._cve_index:
            await self.fetch_catalog()

        cutoff = datetime.now() - timedelta(days=days)
        recent = []

        for entry in self._cve_index.values():
            try:
                entry_date = datetime.strptime(entry.date_added, "%Y-%m-%d")
                if entry_date >= cutoff:
                    recent.append(entry)
            except ValueError:
                continue

        return sorted(recent, key=lambda e: e.date_added, reverse=True)

    @property
    def catalog_size(self) -> int:
        """Get number of CVEs in catalog."""
        return len(self._cve_index)
