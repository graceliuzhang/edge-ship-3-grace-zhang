"""Tests for the password manager track stubs."""

import pytest

import password_manager as pm


def test_register_user_exists_and_unimplemented() -> None:
    assert hasattr(pm, "register_user"), "register_user should exist"
    with pytest.raises(NotImplementedError):
        pm.register_user("user", "pass")


def test_add_password_exists_and_unimplemented() -> None:
    assert hasattr(pm, "add_password"), "add_password should exist"
    with pytest.raises(NotImplementedError):
        pm.add_password("example.com", "user", "password123")


def test_get_passwords_exists_and_unimplemented() -> None:
    assert hasattr(pm, "get_passwords"), "get_passwords should exist"
    with pytest.raises(NotImplementedError):
        pm.get_passwords()