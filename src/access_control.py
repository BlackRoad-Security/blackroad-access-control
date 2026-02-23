"""
BlackRoad Access Control – RBAC engine with SQLite persistence.
Implements: roles, permissions, assignments, audit log, policy evaluation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Set


# ─────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────

@dataclass
class Permission:
    resource: str
    action: str
    conditions: Dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.resource}:{self.action}"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Permission):
            return NotImplemented
        return self.resource == other.resource and self.action == other.action

    def __hash__(self) -> int:
        return hash(self.key)

    def matches(self, resource: str, action: str) -> bool:
        """Support wildcard '*' for resource or action."""
        r_match = self.resource == "*" or self.resource == resource
        a_match = self.action == "*" or self.action == action
        return r_match and a_match


@dataclass
class Role:
    name: str
    description: str = ""
    parent: Optional[str] = None   # role inheritance
    permissions: List[Permission] = field(default_factory=list)

    def has_permission(self, resource: str, action: str) -> bool:
        return any(p.matches(resource, action) for p in self.permissions)


@dataclass
class AccessDecision:
    subject: str
    resource: str
    action: str
    granted: bool
    reason: str
    matched_role: str = ""
    matched_permission: str = ""


# ─────────────────────────────────────────────
# Database
# ─────────────────────────────────────────────

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS roles (
    name        TEXT PRIMARY KEY,
    description TEXT DEFAULT '',
    parent      TEXT DEFAULT NULL,
    created_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS permissions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    role_name   TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
    resource    TEXT NOT NULL,
    action      TEXT NOT NULL,
    conditions  TEXT DEFAULT '{}',
    created_at  TEXT DEFAULT (datetime('now')),
    UNIQUE(role_name, resource, action)
);

CREATE TABLE IF NOT EXISTS assignments (
    subject     TEXT NOT NULL,
    role_name   TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
    granted_by  TEXT DEFAULT 'system',
    granted_at  TEXT DEFAULT (datetime('now')),
    expires_at  TEXT DEFAULT NULL,
    PRIMARY KEY(subject, role_name)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT    NOT NULL,
    subject     TEXT    NOT NULL,
    resource    TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    granted     INTEGER NOT NULL,
    reason      TEXT    DEFAULT '',
    matched_role TEXT   DEFAULT '',
    ip_address  TEXT    DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_subject ON audit_log(subject);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_assign_subject ON assignments(subject);
"""


class AccessControlDB:
    def __init__(self, db_path: str = "access_control.db"):
        self.db_path = db_path
        self._init_db()

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(DB_SCHEMA)


# ─────────────────────────────────────────────
# RBAC Engine
# ─────────────────────────────────────────────

class RBACEngine:
    def __init__(self, db_path: str = "access_control.db"):
        self.db = AccessControlDB(db_path)
        # Seed built-in roles on first run
        self._seed_defaults()

    def _seed_defaults(self) -> None:
        with self.db._conn() as conn:
            row = conn.execute("SELECT COUNT(*) FROM roles").fetchone()
            if row[0] == 0:
                conn.execute("INSERT INTO roles (name,description) VALUES (?,?)",
                             ("admin", "Full access to all resources"))
                conn.execute("INSERT INTO roles (name,description) VALUES (?,?)",
                             ("viewer", "Read-only access"))
                conn.execute("INSERT INTO roles (name,description) VALUES (?,?)",
                             ("editor", "Read and write access"))
                conn.execute("INSERT INTO permissions (role_name,resource,action) VALUES (?,?,?)",
                             ("admin", "*", "*"))
                conn.execute("INSERT INTO permissions (role_name,resource,action) VALUES (?,?,?)",
                             ("viewer", "*", "read"))
                conn.execute("INSERT INTO permissions (role_name,resource,action) VALUES (?,?,?)",
                             ("editor", "*", "read"))
                conn.execute("INSERT INTO permissions (role_name,resource,action) VALUES (?,?,?)",
                             ("editor", "*", "write"))

    # ── Role management ──────────────────────

    def add_role(self, role: Role) -> None:
        """Create or update a role."""
        with self.db._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO roles (name, description, parent) VALUES (?,?,?)",
                (role.name, role.description, role.parent),
            )
            for perm in role.permissions:
                conn.execute(
                    "INSERT OR IGNORE INTO permissions (role_name, resource, action, conditions) "
                    "VALUES (?,?,?,?)",
                    (role.name, perm.resource, perm.action, json.dumps(perm.conditions)),
                )

    def delete_role(self, role_name: str) -> bool:
        with self.db._conn() as conn:
            cur = conn.execute("DELETE FROM roles WHERE name=?", (role_name,))
            return cur.rowcount > 0

    def get_role(self, name: str) -> Optional[Role]:
        with self.db._conn() as conn:
            row = conn.execute("SELECT * FROM roles WHERE name=?", (name,)).fetchone()
            if not row:
                return None
            perms = conn.execute(
                "SELECT resource, action, conditions FROM permissions WHERE role_name=?", (name,)
            ).fetchall()
            return Role(
                name=row["name"],
                description=row["description"],
                parent=row["parent"],
                permissions=[
                    Permission(p["resource"], p["action"],
                               json.loads(p["conditions"] or "{}"))
                    for p in perms
                ],
            )

    def list_roles(self) -> List[str]:
        with self.db._conn() as conn:
            return [r["name"] for r in conn.execute("SELECT name FROM roles ORDER BY name")]

    # ── Permission management ────────────────

    def assign_permission(self, role_name: str, resource: str, action: str,
                          conditions: Optional[Dict] = None) -> bool:
        with self.db._conn() as conn:
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO permissions (role_name, resource, action, conditions) "
                    "VALUES (?,?,?,?)",
                    (role_name, resource, action, json.dumps(conditions or {})),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def revoke_permission(self, role_name: str, resource: str, action: str) -> bool:
        with self.db._conn() as conn:
            cur = conn.execute(
                "DELETE FROM permissions WHERE role_name=? AND resource=? AND action=?",
                (role_name, resource, action),
            )
            return cur.rowcount > 0

    # ── Subject ↔ Role assignments ───────────

    def assign_role(self, subject: str, role_name: str, granted_by: str = "system",
                    expires_at: Optional[str] = None) -> bool:
        with self.db._conn() as conn:
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO assignments "
                    "(subject, role_name, granted_by, expires_at) VALUES (?,?,?,?)",
                    (subject, role_name, granted_by, expires_at),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def revoke_role(self, subject: str, role_name: str) -> bool:
        with self.db._conn() as conn:
            cur = conn.execute(
                "DELETE FROM assignments WHERE subject=? AND role_name=?",
                (subject, role_name),
            )
            return cur.rowcount > 0

    def get_subject_roles(self, subject: str) -> List[str]:
        with self.db._conn() as conn:
            now = datetime.now(timezone.utc).isoformat()
            rows = conn.execute(
                "SELECT role_name FROM assignments "
                "WHERE subject=? AND (expires_at IS NULL OR expires_at > ?)",
                (subject, now),
            ).fetchall()
            return [r["role_name"] for r in rows]

    # ── Effective permissions ────────────────

    def get_effective_permissions(self, subject: str) -> Set[str]:
        """Resolve all permissions for *subject* including inherited roles."""
        visited: Set[str] = set()
        perms: Set[str] = set()
        roles_to_check = list(self.get_subject_roles(subject))
        while roles_to_check:
            role_name = roles_to_check.pop()
            if role_name in visited:
                continue
            visited.add(role_name)
            role = self.get_role(role_name)
            if role is None:
                continue
            for p in role.permissions:
                perms.add(p.key)
            if role.parent and role.parent not in visited:
                roles_to_check.append(role.parent)
        return perms

    # ── Policy evaluation ────────────────────

    def check_permission(self, subject: str, resource: str, action: str) -> AccessDecision:
        roles = self.get_subject_roles(subject)
        for role_name in roles:
            role = self.get_role(role_name)
            if role is None:
                continue
            # Direct permission check (with inheritance)
            chain = [role]
            visited: Set[str] = set()
            while chain:
                r = chain.pop()
                if r.name in visited:
                    continue
                visited.add(r.name)
                for perm in r.permissions:
                    if perm.matches(resource, action):
                        return AccessDecision(
                            subject=subject, resource=resource, action=action,
                            granted=True, reason="permission matched",
                            matched_role=role_name,
                            matched_permission=perm.key,
                        )
                if r.parent:
                    parent = self.get_role(r.parent)
                    if parent:
                        chain.append(parent)
        return AccessDecision(
            subject=subject, resource=resource, action=action,
            granted=False, reason="no matching permission found",
        )

    def policy_evaluate(self, subject: str, resource: str, action: str) -> bool:
        decision = self.check_permission(subject, resource, action)
        self.audit_log_access(subject, resource, action, decision.granted, decision.reason,
                              decision.matched_role)
        return decision.granted

    # ── Audit log ────────────────────────────

    def audit_log_access(self, subject: str, resource: str, action: str,
                         granted: bool, reason: str = "", matched_role: str = "",
                         ip_address: str = "") -> None:
        ts = datetime.now(timezone.utc).isoformat()
        with self.db._conn() as conn:
            conn.execute(
                "INSERT INTO audit_log "
                "(ts, subject, resource, action, granted, reason, matched_role, ip_address) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (ts, subject, resource, action, int(granted),
                 reason, matched_role, ip_address),
            )

    def get_audit_log(self, subject: Optional[str] = None, limit: int = 100) -> List[Dict]:
        with self.db._conn() as conn:
            if subject:
                rows = conn.execute(
                    "SELECT * FROM audit_log WHERE subject=? ORDER BY id DESC LIMIT ?",
                    (subject, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
            return [dict(r) for r in rows]

    # ── Stats ────────────────────────────────

    def stats(self) -> Dict[str, Any]:
        with self.db._conn() as conn:
            roles = conn.execute("SELECT COUNT(*) FROM roles").fetchone()[0]
            perms = conn.execute("SELECT COUNT(*) FROM permissions").fetchone()[0]
            assignments = conn.execute("SELECT COUNT(*) FROM assignments").fetchone()[0]
            denied = conn.execute("SELECT COUNT(*) FROM audit_log WHERE granted=0").fetchone()[0]
            allowed = conn.execute("SELECT COUNT(*) FROM audit_log WHERE granted=1").fetchone()[0]
        return {
            "roles": roles, "permissions": perms,
            "assignments": assignments, "audit_allowed": allowed, "audit_denied": denied,
        }


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="BlackRoad Access Control – RBAC engine")
    p.add_argument("--db", default="access_control.db")
    sub = p.add_subparsers(dest="cmd")

    # check
    ck = sub.add_parser("check", help="Check if subject can perform action on resource")
    ck.add_argument("subject")
    ck.add_argument("resource")
    ck.add_argument("action")

    # assign-role
    ar = sub.add_parser("assign-role", help="Assign a role to a subject")
    ar.add_argument("subject")
    ar.add_argument("role")

    # revoke-role
    rr = sub.add_parser("revoke-role", help="Revoke a role from a subject")
    rr.add_argument("subject")
    rr.add_argument("role")

    # add-role
    nr = sub.add_parser("add-role", help="Create a new role")
    nr.add_argument("name")
    nr.add_argument("--description", default="")
    nr.add_argument("--parent", default=None)

    # add-permission
    ap = sub.add_parser("add-permission", help="Add permission to role")
    ap.add_argument("role")
    ap.add_argument("resource")
    ap.add_argument("action")

    # list-roles
    sub.add_parser("list-roles", help="List all roles")

    # effective
    ef = sub.add_parser("effective", help="Show effective permissions for subject")
    ef.add_argument("subject")

    # audit
    au = sub.add_parser("audit", help="Show audit log")
    au.add_argument("--subject", default=None)
    au.add_argument("--limit", type=int, default=20)

    # stats
    sub.add_parser("stats", help="Show statistics")

    args = p.parse_args(argv)
    engine = RBACEngine(args.db)

    if args.cmd == "check":
        decision = engine.check_permission(args.subject, args.resource, args.action)
        engine.audit_log_access(args.subject, args.resource, args.action,
                                decision.granted, decision.reason, decision.matched_role)
        result = "✅ GRANTED" if decision.granted else "❌ DENIED"
        print(f"{result}: {args.subject} → {args.action} on {args.resource}")
        if decision.matched_role:
            print(f"  Role: {decision.matched_role} | Permission: {decision.matched_permission}")
        return 0 if decision.granted else 1

    elif args.cmd == "assign-role":
        ok = engine.assign_role(args.subject, args.role)
        print(f"{'✅' if ok else '⚠️ '} Assigned role '{args.role}' to '{args.subject}'")

    elif args.cmd == "revoke-role":
        ok = engine.revoke_role(args.subject, args.role)
        print(f"{'✅' if ok else '⚠️ '} Revoked role '{args.role}' from '{args.subject}'")

    elif args.cmd == "add-role":
        engine.add_role(Role(args.name, args.description, args.parent))
        print(f"✅ Role '{args.name}' created")

    elif args.cmd == "add-permission":
        ok = engine.assign_permission(args.role, args.resource, args.action)
        print(f"{'✅' if ok else '⚠️ '} Permission {args.resource}:{args.action} → '{args.role}'")

    elif args.cmd == "list-roles":
        for r in engine.list_roles():
            print(f"  {r}")

    elif args.cmd == "effective":
        perms = engine.get_effective_permissions(args.subject)
        print(f"Effective permissions for '{args.subject}':")
        for perm in sorted(perms):
            print(f"  {perm}")

    elif args.cmd == "audit":
        log = engine.get_audit_log(args.subject, args.limit)
        print(f"{'TS':<25} {'SUBJECT':<20} {'ACTION':<10} {'RESOURCE':<20} {'RESULT'}")
        print("-" * 90)
        for entry in log:
            result = "ALLOW" if entry["granted"] else "DENY"
            print(f"{entry['ts']:<25} {entry['subject']:<20} "
                  f"{entry['action']:<10} {entry['resource']:<20} {result}")

    elif args.cmd == "stats":
        s = engine.stats()
        for k, v in s.items():
            print(f"  {k:<20}: {v}")

    else:
        p.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
