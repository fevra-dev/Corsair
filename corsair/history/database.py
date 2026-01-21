"""
Historical Tracking Database.

SQLite-based persistence for scan results with drift detection.

Features:
- Save and retrieve scan history
- Compare scans over time
- Detect configuration drift
- Generate trend reports
"""

import json
import sqlite3
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from pathlib import Path

from ..models import TargetResult, Finding, FingerprintResult, HistoricalComparison, Severity
from ..utils.logger import get_logger

logger = get_logger(__name__)


# Default database path
DEFAULT_DB_PATH = Path.home() / ".corsair" / "history.db"


class HistoryDatabase:
    """
    SQLite database for scan history persistence.
    
    Usage:
        db = HistoryDatabase()
        
        # Save a scan
        scan_id = db.save_scan(result)
        
        # Get history for a URL
        history = db.get_history("https://example.com", limit=10)
        
        # Compare scans
        comparison = db.compare_scans(scan_id_1, scan_id_2)
    """
    
    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize the history database.
        
        Args:
            db_path: Path to SQLite database file.
                    Defaults to ~/.corsair/history.db
        """
        self.db_path = db_path or DEFAULT_DB_PATH
        self._ensure_directory()
        self._init_database()
        
        logger.info(f"[History] Database initialized at {self.db_path}")
    
    def _ensure_directory(self) -> None:
        """Ensure database directory exists."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
    
    def _init_database(self) -> None:
        """Initialize database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                final_url TEXT,
                scan_date TEXT NOT NULL,
                score INTEGER NOT NULL,
                grade TEXT NOT NULL,
                status_code INTEGER,
                headers_json TEXT,
                findings_json TEXT,
                fingerprints_json TEXT,
                error TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Indexes for fast lookups
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scans_url ON scans(url)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scans_date ON scans(scan_date)
        """)
        
        # Drift alerts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS drift_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                scan_id INTEGER NOT NULL,
                previous_scan_id INTEGER NOT NULL,
                drift_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id),
                FOREIGN KEY (previous_scan_id) REFERENCES scans(id)
            )
        """)
        
        conn.commit()
        conn.close()
        
        logger.debug("[History] Database schema initialized")
    
    def save_scan(self, result: TargetResult) -> int:
        """
        Save a scan result to the database.
        
        Args:
            result: TargetResult to save
            
        Returns:
            Scan ID
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        scan_date = datetime.now().isoformat()
        
        # Serialize findings and fingerprints
        findings_json = json.dumps([f.to_dict() for f in result.findings])
        fingerprints_json = json.dumps([fp.to_dict() for fp in result.fingerprints])
        headers_json = json.dumps(result.headers)
        
        cursor.execute("""
            INSERT INTO scans (
                url, final_url, scan_date, score, grade, status_code,
                headers_json, findings_json, fingerprints_json, error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.url,
            result.final_url,
            scan_date,
            result.score,
            result.grade,
            result.status_code,
            headers_json,
            findings_json,
            fingerprints_json,
            result.error
        ))
        
        scan_id = cursor.lastrowid
        conn.commit()
        
        logger.info(f"[History] Saved scan {scan_id} for {result.url} (score: {result.score})")
        
        # Check for drift
        previous = self._get_previous_scan(cursor, result.url, scan_id)
        if previous:
            self._detect_drift(conn, cursor, scan_id, previous, result)
        
        conn.close()
        
        return scan_id
    
    def _get_previous_scan(
        self,
        cursor: sqlite3.Cursor,
        url: str,
        current_id: int
    ) -> Optional[Dict]:
        """Get the most recent previous scan for a URL."""
        cursor.execute("""
            SELECT id, score, grade, findings_json
            FROM scans
            WHERE url = ? AND id < ?
            ORDER BY scan_date DESC
            LIMIT 1
        """, (url, current_id))
        
        row = cursor.fetchone()
        if row:
            return {
                "id": row[0],
                "score": row[1],
                "grade": row[2],
                "findings": json.loads(row[3])
            }
        return None
    
    def _detect_drift(
        self,
        conn: sqlite3.Connection,
        cursor: sqlite3.Cursor,
        scan_id: int,
        previous: Dict,
        current: TargetResult
    ) -> None:
        """Detect and record configuration drift."""
        alerts = []
        
        # Score drop detection
        score_delta = current.score - previous["score"]
        if score_delta < -10:
            alerts.append({
                "drift_type": "score_drop",
                "severity": "HIGH",
                "description": f"Score dropped from {previous['score']} to {current.score}"
            })
            logger.warning(f"[History] Drift: Score drop for {current.url}")
        
        # New critical/high issues
        current_issues = {
            f["title"] for f in [f.to_dict() for f in current.findings]
            if f["severity"] in ["CRITICAL", "HIGH"]
        }
        previous_issues = {
            f["title"] for f in previous["findings"]
            if f["severity"] in ["CRITICAL", "HIGH"]
        }
        
        new_issues = current_issues - previous_issues
        if new_issues:
            alerts.append({
                "drift_type": "new_issues",
                "severity": "MEDIUM",
                "description": f"New critical/high issues: {', '.join(list(new_issues)[:3])}"
            })
            logger.warning(f"[History] Drift: {len(new_issues)} new issues for {current.url}")
        
        # Save alerts
        for alert in alerts:
            cursor.execute("""
                INSERT INTO drift_alerts (
                    url, scan_id, previous_scan_id,
                    drift_type, severity, description
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                current.url,
                scan_id,
                previous["id"],
                alert["drift_type"],
                alert["severity"],
                alert["description"]
            ))
        
        conn.commit()
    
    def get_history(self, url: str, limit: int = 10) -> List[Dict]:
        """
        Get scan history for a URL.
        
        Args:
            url: URL to get history for
            limit: Maximum number of results
            
        Returns:
            List of scan records (newest first)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, url, final_url, scan_date, score, grade, status_code, error
            FROM scans
            WHERE url = ?
            ORDER BY scan_date DESC
            LIMIT ?
        """, (url, limit))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                "id": row[0],
                "url": row[1],
                "final_url": row[2],
                "scan_date": row[3],
                "score": row[4],
                "grade": row[5],
                "status_code": row[6],
                "error": row[7]
            })
        
        conn.close()
        
        logger.debug(f"[History] Retrieved {len(results)} records for {url}")
        return results
    
    def get_scan(self, scan_id: int) -> Optional[Dict]:
        """
        Get a specific scan by ID.
        
        Args:
            scan_id: Scan ID to retrieve
            
        Returns:
            Scan record or None
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, url, final_url, scan_date, score, grade, status_code,
                   headers_json, findings_json, fingerprints_json, error
            FROM scans
            WHERE id = ?
        """, (scan_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                "id": row[0],
                "url": row[1],
                "final_url": row[2],
                "scan_date": row[3],
                "score": row[4],
                "grade": row[5],
                "status_code": row[6],
                "headers": json.loads(row[7]) if row[7] else {},
                "findings": json.loads(row[8]) if row[8] else [],
                "fingerprints": json.loads(row[9]) if row[9] else [],
                "error": row[10]
            }
        
        return None
    
    def compare_scans(
        self,
        scan_id_1: int,
        scan_id_2: int
    ) -> Optional[HistoricalComparison]:
        """
        Compare two scans.
        
        Args:
            scan_id_1: First (older) scan ID
            scan_id_2: Second (newer) scan ID
            
        Returns:
            HistoricalComparison or None if scans not found
        """
        scan1 = self.get_scan(scan_id_1)
        scan2 = self.get_scan(scan_id_2)
        
        if not scan1 or not scan2:
            return None
        
        # Get issue titles
        issues1 = {f["title"] for f in scan1["findings"] if f["severity"] != "PASS"}
        issues2 = {f["title"] for f in scan2["findings"] if f["severity"] != "PASS"}
        
        new_issues = list(issues2 - issues1)
        resolved_issues = list(issues1 - issues2)
        unchanged_issues = list(issues1 & issues2)
        
        return HistoricalComparison(
            previous_scan_date=scan1["scan_date"],
            previous_score=scan1["score"],
            score_delta=scan2["score"] - scan1["score"],
            new_issues=new_issues,
            resolved_issues=resolved_issues,
            unchanged_issues=unchanged_issues
        )
    
    def get_drift_alerts(
        self,
        url: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict]:
        """
        Get drift alerts.
        
        Args:
            url: Optional URL filter
            limit: Maximum results
            
        Returns:
            List of drift alerts
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if url:
            cursor.execute("""
                SELECT id, url, scan_id, previous_scan_id,
                       drift_type, severity, description, created_at
                FROM drift_alerts
                WHERE url = ?
                ORDER BY created_at DESC
                LIMIT ?
            """, (url, limit))
        else:
            cursor.execute("""
                SELECT id, url, scan_id, previous_scan_id,
                       drift_type, severity, description, created_at
                FROM drift_alerts
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                "id": row[0],
                "url": row[1],
                "scan_id": row[2],
                "previous_scan_id": row[3],
                "drift_type": row[4],
                "severity": row[5],
                "description": row[6],
                "created_at": row[7]
            })
        
        conn.close()
        return results
    
    def get_statistics(self, url: str) -> Dict:
        """
        Get statistics for a URL.
        
        Args:
            url: URL to get stats for
            
        Returns:
            Statistics dictionary
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total scans
        cursor.execute("SELECT COUNT(*) FROM scans WHERE url = ?", (url,))
        total_scans = cursor.fetchone()[0]
        
        # Average score
        cursor.execute("SELECT AVG(score) FROM scans WHERE url = ?", (url,))
        avg_score = cursor.fetchone()[0] or 0
        
        # Score trend (last 5 scans)
        cursor.execute("""
            SELECT score FROM scans
            WHERE url = ?
            ORDER BY scan_date DESC
            LIMIT 5
        """, (url,))
        recent_scores = [row[0] for row in cursor.fetchall()]
        
        # Drift alerts count
        cursor.execute("SELECT COUNT(*) FROM drift_alerts WHERE url = ?", (url,))
        drift_alerts = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "total_scans": total_scans,
            "average_score": round(avg_score, 1),
            "recent_scores": recent_scores,
            "drift_alerts": drift_alerts,
            "trend": self._calculate_trend(recent_scores)
        }
    
    def _calculate_trend(self, scores: List[int]) -> str:
        """Calculate trend from recent scores."""
        if len(scores) < 2:
            return "stable"
        
        # Compare newest to oldest
        delta = scores[0] - scores[-1]
        if delta > 5:
            return "improving"
        elif delta < -5:
            return "declining"
        return "stable"
    
    def cleanup(self, days: int = 90) -> int:
        """
        Delete old scan records.
        
        Args:
            days: Delete records older than this many days
            
        Returns:
            Number of deleted records
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cutoff = datetime.now().isoformat()[:10]  # Just date part
        
        cursor.execute("""
            DELETE FROM scans
            WHERE date(scan_date) < date(?, '-' || ? || ' days')
        """, (cutoff, days))
        
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        
        logger.info(f"[History] Cleaned up {deleted} records older than {days} days")
        return deleted
