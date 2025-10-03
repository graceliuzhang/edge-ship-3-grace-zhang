# Ship 3 Plan – Choose Your Project

This document outlines the tasks to complete during Ship 3 (Oct 1 – Oct 6).

## Tasks

1. **Create your own repository.**  Fork or clone this template into your
   personal GitHub account.  Make it public, enable branch protection on
   `main`, and require pull requests for merges.
2. **Pick a project track.**  Choose one of the three starter projects:
   * **Choose‑Your‑Own‑Adventure Game** – Build a text‑based story engine that reads a story file and lets the user make choices.  Best practices include planning your narrative and using loops and conditional logic for branching【87470855452451†L60-L90】.
   * **Password Manager** – Build a CLI tool to store login credentials in an encrypted JSON file.  Tutorials suggest keeping saved passwords and user credentials in separate files and encrypting them with a library like `cryptography.fernet`【378625587438318†L81-L96】.
   * **Flashcard Quiz App** – Build an application to manage flashcards and quiz yourself.  You will add features like random question selection and scoring in later ships.
3. **Write your proposal.**  Document your choice in `project-proposal.md`.  Describe the problem your program will solve, the features you want to implement and any stretch goals.
4. **Practise Git.**  Create a feature branch, make at least two meaningful commits while working on your proposal, and open a pull request.  Merge it back into `main` once reviewed.
5. **Verify your environment.**  Run each Python script to see the greeting and run the tests with `pytest` to ensure the stubs exist and raise `NotImplementedError`.

## Looking Ahead

In Ship 4 you will implement the first core functionality for your chosen track:

* **Adventure Game:** Load a story from a JSON file and present the first choice to the user.  Use simple functions and loops to handle input.
* **Password Manager:** Write functions to register a user (store hashed master password) and add a password entry to a JSON file.
* **Quiz App:** Implement adding flashcards to a JSON file and list them to the user.

Subsequent ships will add editing/deleting, sorting/searching, testing & documentation, optional enhancements and final polish.