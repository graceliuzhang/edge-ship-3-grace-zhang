"""Tests for the flashcard quiz track stubs."""

import pytest

import quiz_game as qg


def test_add_flashcard_exists_and_unimplemented() -> None:
    assert hasattr(qg, "add_flashcard"), "add_flashcard should exist"
    with pytest.raises(NotImplementedError):
        qg.add_flashcard("What is 2+2?", "4")


def test_start_quiz_exists_and_unimplemented() -> None:
    assert hasattr(qg, "start_quiz"), "start_quiz should exist"
    with pytest.raises(NotImplementedError):
        qg.start_quiz()


def test_list_flashcards_exists_and_unimplemented() -> None:
    assert hasattr(qg, "list_flashcards"), "list_flashcards should exist"
    with pytest.raises(NotImplementedError):
        qg.list_flashcards()