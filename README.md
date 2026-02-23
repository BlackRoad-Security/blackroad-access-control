# blackroad-access-control

Production RBAC (Role-Based Access Control) engine with SQLite persistence and full audit logging.

## Features

- 🔐 **RBAC Engine** – Roles, permissions, wildcard `*` resources/actions
- 📦 **Role Inheritance** – Hierarchical roles with permission resolution
- 🕐 **Expiring Assignments** – Time-limited role grants
- 📝 **Audit Log** – Every access decision logged with subject/resource/action/result
- 💾 **SQLite Persistence** – Zero-dependency storage

## Built-in Roles

| Role | Permissions |
|------|-------------|
| `admin` | `*:*` (all resources, all actions) |
| `viewer` | `*:read` |
| `editor` | `*:read`, `*:write` |

## Usage

```bash
# Check permission
python src/access_control.py check alice documents read

# Assign role
python src/access_control.py assign-role alice editor

# Create custom role
python src/access_control.py add-role deployer --description "Deploy access"

# Add permission to role
python src/access_control.py add-permission deployer deployment execute

# Effective permissions
python src/access_control.py effective alice

# Audit log
python src/access_control.py audit --subject alice
```

## Schema

- `roles` – role definitions with optional parent
- `permissions` – resource:action grants per role  
- `assignments` – subject → role mappings (with expiry)
- `audit_log` – timestamped access decisions

## Tests

```bash
pytest tests/ -v --cov=src
```

## License

Proprietary – BlackRoad OS, Inc. All rights reserved.