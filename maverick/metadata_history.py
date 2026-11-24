"""Read-only bounded metadata windows; no private body or persistent search index."""
from __future__ import annotations
SQLITE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_goals_owner_created_history ON goals(owner,created_at,id)",
    "CREATE INDEX IF NOT EXISTS idx_projects_owner_created_history ON projects(owner,created_at,id)",
    "CREATE INDEX IF NOT EXISTS idx_facts_shared_updated_history ON facts(updated_at,key) WHERE LOWER(key) NOT LIKE 'user:%' AND LOWER(key) NOT LIKE 'goal:%'",
]
POSTGRES_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_goals_owner_created_history ON goals(tenant_id,owner,created_at,id)",
    "CREATE INDEX IF NOT EXISTS idx_projects_owner_created_history ON projects(tenant_id,owner,created_at,id)",
    "CREATE INDEX IF NOT EXISTS idx_facts_shared_updated_history ON facts(tenant_id,updated_at,key) WHERE LOWER(key) NOT LIKE 'user:%' AND LOWER(key) NOT LIKE 'goal:%'",
]
