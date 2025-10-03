"""Choose‑Your‑Own‑Adventure game engine (stub).

This module provides placeholder functions for a text‑based adventure game.
In Ship 3 you will implement the `load_story` and `start_game` functions so
the game can load a small story file and present the first scene.  Additional
features such as menus, replay loops and advanced state management come in
later ships.
"""

def load_story(file_path: str) -> dict:
    """Load a story definition from a file and return it as a data structure.

    The story file might be JSON, YAML or a custom format.  In Ship 3 you
    will parse the file and return a dictionary or another structure
    representing the narrative so you can display the opening scene.

    Args:
        file_path: Path to the story file.

    Returns:
        A dictionary describing the story and its choices.
    """
    raise NotImplementedError("load_story is not yet implemented")


def start_game(story: dict) -> None:
    """Begin the adventure using the provided story data.

    This function will handle user input, present choices and traverse
    the story graph.  In Ship 3 you will get it to print the first scene
    and prompt for a choice; later ships expand it with loops and state.

    Args:
        story: The story data structure returned by `load_story`.
    """
    raise NotImplementedError("start_game is not yet implemented")


def main() -> None:
    """Entry point for the adventure game.

    When run directly, this prints a greeting.  You will replace this
    with calls to `load_story` and `start_game` after implementing them.
    """
    print("Welcome to the Choose‑Your‑Own‑Adventure game!")


if __name__ == "__main__":
    main()