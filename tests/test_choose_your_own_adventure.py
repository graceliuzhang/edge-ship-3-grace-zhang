"""Tests for the choose‑your‑own‑adventure track stubs."""

import pytest

import choose_your_own_adventure as cyoa


def test_load_story_exists_and_unimplemented() -> None:
    assert hasattr(cyoa, "load_story"), "load_story should exist"
    with pytest.raises(NotImplementedError):
        cyoa.load_story("story.json")


def test_start_game_exists_and_unimplemented() -> None:
    assert hasattr(cyoa, "start_game"), "start_game should exist"
    with pytest.raises(NotImplementedError):
        cyoa.start_game({})