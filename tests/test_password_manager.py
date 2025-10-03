"""Tests for the password manager implemented functions."""

import os
import pathlib
import pytest

import password_manager as pm


def test_register_and_verify_user(tmp_path: pathlib.Path) -> None:
    # Run inside a temporary directory so we don't touch repo data
    orig_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        # Register a user then verify
        pm.register_user("alice", "s3cret")
        assert pm.verify_user("alice", "s3cret") is True
        assert pm.verify_user("alice", "wrong") is False

        # Duplicate registration should raise
        with pytest.raises(ValueError):
            pm.register_user("alice", "another")
    finally:
        os.chdir(orig_cwd)


def test_verify_nonexistent_user(tmp_path: pathlib.Path) -> None:
    orig_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        assert pm.verify_user("noone", "pass") is False
    finally:
        os.chdir(orig_cwd)


def test_add_and_get_password_encrypted(tmp_path: pathlib.Path) -> None:
    orig_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        # Register user
        pm.register_user("bob", "hunter2")

        # Add a site password
        pm.add_password_encrypted("example.com", "bob", "sitepass", "hunter2")

        items = pm.get_passwords_encrypted("bob", "hunter2")
        assert len(items) == 1
        assert items[0]["site"] == "example.com"
        assert items[0]["password"] == "sitepass"
    finally:
        os.chdir(orig_cwd)


def test_add_and_get_wrong_master_fails(tmp_path: pathlib.Path) -> None:
    orig_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        pm.register_user("carol", "topsecret")
        pm.add_password_encrypted("foo.com", "carol", "p@ssw0rd", "topsecret")
        with pytest.raises(ValueError):
            pm.get_passwords_encrypted("carol", "wrongpass")
    finally:
        os.chdir(orig_cwd)