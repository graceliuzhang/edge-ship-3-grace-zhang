"""Simple password manager (stub).

This module provides placeholder functions for a command‑line password
manager.  Eventually it will allow users to register with a master
password, store encrypted passwords for various sites and retrieve them.
For now, it contains stubs that raise `NotImplementedError` and prints
a greeting when executed.
"""

def register_user(username: str, master_password: str) -> None:
    """Register a new user with a master password.

    You will hash and store the master password in a
    JSON file for authentication.  This stub does nothing.

    Args:
        username: The username for the account.
        master_password: The master password to use.
    """
    raise NotImplementedError("register_user is not yet implemented")


def add_password(site: str, username: str, password: str) -> None:
    """Store a password for a given site.

    You will encrypt the password and save it to a JSON file,
    associating it with the site and username.  This stub does nothing.

    Args:
        site: The website or service name.
        username: The account username for the site.
        password: The password to store.
    """
    raise NotImplementedError("add_password is not yet implemented")


def get_passwords() -> list[dict]:
    """Retrieve all stored passwords.

    This will read from an encrypted JSON file and return a list
    of dictionaries containing site, username and password.  For now
    it raises `NotImplementedError`.

    Returns:
        A list of stored passwords.
    """
    raise NotImplementedError("get_passwords is not yet implemented")


def main() -> None:
    """Entry point for the password manager.

    When run directly, this prints a greeting.  You will replace this
    with registration, login and menu functionality in future ships.
    """
    print("Welcome to the Password Manager!")


if __name__ == "__main__":
    main()