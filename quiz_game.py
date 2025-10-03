"""Flashcard quiz application (stub).

This module provides placeholder functions for a flashcard/quiz program.
It will allow users to add flashcards and quiz themselves.  For now,
the functions raise `NotImplementedError` and the script prints a
greeting when run.
"""

def add_flashcard(question: str, answer: str) -> None:
    """Add a new flashcard to the collection.

    You will store flashcards in a JSON file or another data
    structure.  This stub does nothing.

    Args:
        question: The question text.
        answer: The answer text.
    """
    raise NotImplementedError("add_flashcard is not yet implemented")


def list_flashcards() -> list[dict]:
    """Retrieve all flashcards from storage.

    This function will load the stored flashcards and return them.  You
    you should implement reading from `data/flashcards.json` and return a
    list of dictionaries with `question` and `answer` keys.  Right now it
    raises `NotImplementedError`.

    Returns:
        A list of flashcards.
    """
    raise NotImplementedError("list_flashcards is not yet implemented")


def start_quiz() -> None:
    """Run the quiz loop.

    This will retrieve stored flashcards, prompt the user for
    answers and track their score.  For now it raises
    `NotImplementedError`.
    """
    raise NotImplementedError("start_quiz is not yet implemented")


def main() -> None:
    """Entry point for the quiz app.

    When run directly, this prints a greeting.  You will replace this
    with menu logic in later ships.
    """
    print("Welcome to the Flashcard Quiz App!")


if __name__ == "__main__":
    main()