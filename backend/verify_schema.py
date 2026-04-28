#!/usr/bin/env python3
"""Verify the migration-managed database schema."""

from sqlalchemy import inspect

from app.database import engine

inspector = inspect(engine)
tables = inspector.get_table_names()

print("=" * 70)
print("DATABASE SCHEMA VERIFICATION")
print("=" * 70)

core_tables = {
    "users": "User accounts with roles",
    "network_snapshots": "Snapshot metadata and stored topology",
    "network_nodes": "Normalized topology nodes",
    "network_edges": "Normalized topology edges",
    "vulnerabilities": "CVEs and vulnerability metadata",
    "attack_paths": "Predicted attack path records",
    "remediation_plans": "Persisted remediation recommendations",
}

infrastructure_tables = {
    "refresh_tokens": "Reserved for refresh-token rotation",
    "audit_logs": "Reserved for backend audit trail",
    "jobs": "Reserved for async job orchestration",
    "exports": "Reserved for export/report tracking",
    "alembic_version": "Migration state tracking",
}

print("\nCORE TABLES:")
for table_name, description in core_tables.items():
    exists = "OK" if table_name in tables else "MISSING"
    print(f"  {exists:<7} {table_name:<20} - {description}")

print("\nINFRASTRUCTURE TABLES:")
for table_name, description in infrastructure_tables.items():
    exists = "OK" if table_name in tables else "MISSING"
    print(f"  {exists:<7} {table_name:<20} - {description}")

print("\n" + "=" * 70)
print("COLUMN DETAILS")
print("=" * 70)

for table_name in [*core_tables.keys(), *infrastructure_tables.keys()]:
    if table_name not in tables:
        continue
    print(f"\n{table_name}:")
    for column in inspector.get_columns(table_name):
        nullable = "NULL" if column["nullable"] else "NOT NULL"
        print(f"  - {column['name']:<28} {str(column['type']):<20} {nullable}")

print("\n" + "=" * 70)
print("NEXT STEPS")
print("=" * 70)
print("1. Run migrations with: alembic -c backend/alembic.ini upgrade head")
print("2. Start the backend only after migrations succeed")
print("3. Verify persisted analysis data in snapshots, nodes, edges, and attack_paths")
print("4. Keep new infrastructure tables empty until later backend steps implement them")
