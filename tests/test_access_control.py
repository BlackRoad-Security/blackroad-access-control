"""Tests for blackroad-access-control."""
import sys, os, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from src.access_control import RBACEngine, Role, Permission


@pytest.fixture
def engine(tmp_path):
    return RBACEngine(str(tmp_path / "test_rbac.db"))


def test_default_roles_exist(engine):
    roles = engine.list_roles()
    assert "admin" in roles
    assert "viewer" in roles


def test_assign_check_permission(engine):
    engine.assign_role("alice", "admin")
    assert engine.policy_evaluate("alice", "resource", "delete")


def test_viewer_read_only(engine):
    engine.assign_role("bob", "viewer")
    assert engine.check_permission("bob", "anything", "read").granted
    assert not engine.check_permission("bob", "anything", "write").granted


def test_custom_role(engine):
    r = Role("deployer", "Can deploy", permissions=[Permission("deployment", "execute")])
    engine.add_role(r)
    engine.assign_role("charlie", "deployer")
    assert engine.check_permission("charlie", "deployment", "execute").granted
    assert not engine.check_permission("charlie", "deployment", "delete").granted


def test_wildcard_permission(engine):
    engine.assign_role("superuser", "admin")
    assert engine.check_permission("superuser", "anything", "anything").granted


def test_effective_permissions(engine):
    engine.assign_role("dave", "editor")
    perms = engine.get_effective_permissions("dave")
    assert "*:read" in perms or any("read" in p for p in perms)


def test_revoke_role(engine):
    engine.assign_role("eve", "viewer")
    engine.revoke_role("eve", "viewer")
    assert not engine.check_permission("eve", "doc", "read").granted


def test_audit_log(engine):
    engine.assign_role("frank", "admin")
    engine.policy_evaluate("frank", "db", "read")
    log = engine.get_audit_log("frank")
    assert len(log) >= 1
    assert log[0]["subject"] == "frank"


def test_stats(engine):
    s = engine.stats()
    assert "roles" in s
    assert s["roles"] >= 3  # admin + viewer + editor
