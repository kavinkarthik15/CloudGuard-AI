"""
ScannerProvider interface (Protocol).

Session 1: SimulatedScannerProvider (loads JSON fixtures) implements this.
Session 2: Boto3ScannerProvider will implement this to call real AWS APIs
           without modifying any Analyzer or Scanner logic.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from models import S3BucketConfig, SecurityGroupConfig


@runtime_checkable
class ScannerProvider(Protocol):
    """Abstract interface for resource data providers.

    Implementations must supply both methods below. The Analyzer and Scanner
    depend only on this interface and are unaware of whether data comes from
    JSON fixtures (Session 1) or real AWS APIs (Session 2).
    """

    def list_s3_buckets(self) -> list[S3BucketConfig]:
        """Return all S3 bucket configurations to be analyzed."""
        ...

    def list_security_groups(self, region: str) -> list[SecurityGroupConfig]:
        """Return all EC2 security group configurations for the given region."""
        ...
