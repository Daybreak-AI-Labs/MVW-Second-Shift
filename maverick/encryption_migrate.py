"""Seal existing plaintext data after at-rest encryption is enabled.

Enabling at-rest encryption (``[encryption] at_rest``) only seals **new** writes;
rows written before are left plaintext and read back transparently (lazy
migration). This module force-seals that pre-existing plaintext so the whole
store is encrypted, not just new data. It is **idempotent** — already-bound
values are skipped and legacy sealed values are rebound — so it is safe to re-run.

The reseal happens **in place**. SQLite shreds the pre-encryption plaintext residue
(``secure_delete`` + VACUUM); Postgres uses a tenant-scoped transaction and marker.
SQLite operators who need a rollback copy may explicitly opt in to a
transactionally-consistent **plaintext backup** (:func:`backup_world_db`).

Exposed as ``maverick encryption migrate [--dry-run] [--backup]``.
"""
from __future__ import annotations


def postgres_migration_scope(tenant: str | None) -> str:
    """Collision-free marker identity, including legacy rows without a tenant."""
    return "n:" if tenant is None else "t:" + tenant


__all__ = [
]
