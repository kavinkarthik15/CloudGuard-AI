"""
SimulatedScannerProvider — Session 1 implementation of ScannerProvider.

Loads resource configurations from JSON fixture files on disk.
Does NOT make any network calls. Does NOT import boto3.

Session 2 will add Boto3ScannerProvider in providers/boto3_provider.py
without modifying this file or any Analyzer logic.
"""
from __future__ import annotations

import json
from pathlib import Path

from models import S3BucketConfig, SecurityGroupConfig

# Fixture files are stored relative to the backend/ directory
_FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


class SimulatedScannerProvider:
    """Loads simulated AWS resource configurations from JSON fixture files.

    This provider is entirely self-contained and makes no network calls.
    All resource names and IDs in the fixtures are clearly fictitious.
    """

    def __init__(self, fixtures_dir: Path | None = None) -> None:
        self._fixtures_dir = fixtures_dir or _FIXTURES_DIR

    def _load_fixture(self, filename: str) -> list[dict]:
        """Load and parse a JSON fixture file."""
        path = self._fixtures_dir / filename
        if not path.exists():
            raise RuntimeError(
                f"Fixture file not found: {path}. "
                "Ensure backend/fixtures/ contains the required JSON files."
            )
        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"Failed to parse fixture file {path}: {exc}"
            ) from exc
        if not isinstance(data, list):
            raise RuntimeError(
                f"Fixture file {path} must contain a JSON array, got {type(data).__name__}."
            )
        return data

    def list_s3_buckets(self) -> list[S3BucketConfig]:
        """Return simulated S3 bucket configurations from fixtures."""
        raw = self._load_fixture("s3_buckets.json")
        buckets = []
        for item in raw:
            try:
                buckets.append(S3BucketConfig.model_validate(item))
            except Exception as exc:
                raise RuntimeError(
                    f"Invalid S3 bucket fixture entry {item.get('name', '?')}: {exc}"
                ) from exc
        return buckets

    def list_security_groups(self, region: str) -> list[SecurityGroupConfig]:
        """Return simulated EC2 security group configurations from fixtures."""
        raw = self._load_fixture("security_groups.json")
        groups = []
        for item in raw:
            try:
                groups.append(SecurityGroupConfig.model_validate(item))
            except Exception as exc:
                raise RuntimeError(
                    f"Invalid security group fixture entry {item.get('group_id', '?')}: {exc}"
                ) from exc
        return groups
