import json
import os

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
    if not username or not master_password:
        raise ValueError("Username and password cannot be empty")

    # File to store users. Keep in repo data directory.
    user_data_file = os.path.join("data", "passwords.json")

    # Load existing users
    if os.path.exists(user_data_file):
        with open(user_data_file, "r", encoding="utf-8") as f:
            try:
                users = json.load(f)
            except json.JSONDecodeError:
                users = {}
        # If the file contains a non-dict (e.g., an empty list), reset to {}
        if not isinstance(users, dict):
            users = {}
    else:
        users = {}

    if username in users:
        raise ValueError("Username already exists")

    # Parameters for PBKDF2
    algorithm = "pbkdf2_sha256"
    iterations = 100_000
    salt = os.urandom(16)

    # Derive key
    dk = _hash_password(master_password, salt, iterations)

    users[username] = {
        "algorithm": algorithm,
        "iterations": iterations,
        "salt": salt.hex(),
        "hash": dk.hex(),
    }

    # Atomic write: write to temp file then replace
    tmp_file = user_data_file + ".tmp"
    os.makedirs(os.path.dirname(user_data_file), exist_ok=True)
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)
    os.replace(tmp_file, user_data_file)


def add_password(site: str, username: str, password: str) -> None:
    """Store a password for a given site.

    You will encrypt the password and save it to a JSON file,
    associating it with the site and username.  This stub does nothing.

    Args:
        site: The website or service name.
        username: The account username for the site.
        password: The password to store.
    """
    # This function requires the user's master password to encrypt the
    # site password. For a stdlib-only implementation we derive an
    # encryption key from the user's master password and user's salt
    # then XOR the plaintext with a PBKDF2-derived keystream using a
    # per-entry nonce. We also store an HMAC tag to detect wrong
    # master passwords on decryption.
    raise NotImplementedError(
        "add_password requires master password; use add_password_encrypted"
    )


def add_password_encrypted(site: str, account_username: str, password: str, master_password: str) -> None:
    """Encrypt and store a site password for a user.

    Args:
        site: website/service name
        account_username: username for the site
        password: plaintext password to store
        master_password: user's master password (used to derive encryption key)

    Raises:
        ValueError: if user does not exist or inputs invalid
    """
    if not site or not account_username or not password:
        raise ValueError("site, account_username and password are required")

    user_data_file = os.path.join("data", "passwords.json")
    if not os.path.exists(user_data_file):
        raise ValueError("no users registered")

    with open(user_data_file, "r", encoding="utf-8") as f:
        try:
            users = json.load(f)
        except json.JSONDecodeError:
            raise ValueError("user data corrupted")

    if not isinstance(users, dict):
        raise ValueError("user data corrupted")

    record = users.get(account_username)
    if not record:
        raise ValueError("user not found")

    # Derive encryption key from master password and user's stored salt
    salt = bytes.fromhex(record["salt"])
    iterations = int(record.get("iterations", 100_000))
    enc_key = _derive_encryption_key(master_password, salt, iterations)

    nonce, ciphertext, tag = _encrypt_password(enc_key, password)

    # Append to user's vault list
    vault = record.get("vault")
    if vault is None:
        vault = []
    vault.append({
        "site": site,
        "username": account_username,
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex(),
    })
    record["vault"] = vault

    # Save back atomically
    tmp_file = user_data_file + ".tmp"
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)
    os.replace(tmp_file, user_data_file)


def get_passwords() -> list[dict]:
    """Retrieve all stored passwords.

    This will read from an encrypted JSON file and return a list
    of dictionaries containing site, username and password.  For now
    it raises `NotImplementedError`.

    Returns:
        A list of stored passwords.
    """
    # Backwards-compatible behavior: some projects expect a simple
    # `data/passwords.json` containing a top-level list of password
    # entries like [{"site":..., "username":..., "password":...}, ...]
    user_data_file = os.path.join("data", "passwords.json")
    if not os.path.exists(user_data_file):
        return []

    with open(user_data_file, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return []

    # If the file is already a list of entries, return directly (legacy)
    if isinstance(data, list):
        return data

    # If the file is a dict (our current users-vault structure), we cannot
    # return decrypted passwords without the user's master password.
    # Use `get_passwords_encrypted(username, master_password)` instead.
    raise NotImplementedError(
        "get_passwords for encrypted vaults requires a master password; use get_passwords_encrypted(username, master_password)"
    )


def get_passwords_encrypted(account_username: str, master_password: str) -> list[dict]:
    """Retrieve and decrypt stored site passwords for a user.

    Args:
        account_username: the registered username
        master_password: the user's master password for decryption

    Returns:
        list of dicts with keys: site, username, password

    Raises:
        ValueError: if user not found or master password invalid
    """
    user_data_file = os.path.join("data", "passwords.json")
    if not os.path.exists(user_data_file):
        raise ValueError("no users registered")

    with open(user_data_file, "r", encoding="utf-8") as f:
        try:
            users = json.load(f)
        except json.JSONDecodeError:
            raise ValueError("user data corrupted")

    if not isinstance(users, dict):
        raise ValueError("user data corrupted")

    record = users.get(account_username)
    if not record:
        raise ValueError("user not found")

    vault = record.get("vault", [])
    if not vault:
        return []

    salt = bytes.fromhex(record["salt"])
    iterations = int(record.get("iterations", 100_000))
    enc_key = _derive_encryption_key(master_password, salt, iterations)

    results = []
    for entry in vault:
        nonce = bytes.fromhex(entry["nonce"])
        ciphertext = bytes.fromhex(entry["ciphertext"])
        tag = bytes.fromhex(entry["tag"])
        try:
            plaintext = _decrypt_password(enc_key, nonce, ciphertext, tag)
        except ValueError:
            # Tag mismatch -> wrong master password or tampered data
            raise ValueError("invalid master password or corrupted vault")
        results.append({"site": entry["site"], "username": entry["username"], "password": plaintext})

    return results


def _derive_encryption_key(master_password: str, salt: bytes, iterations: int) -> bytes:
    """Derive a 32-byte encryption key from the master password and salt."""
    if isinstance(master_password, str):
        master_password = master_password.encode("utf-8")
    return __import__("hashlib").pbkdf2_hmac("sha256", master_password, salt, iterations, dklen=32)


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _encrypt_password(key: bytes, plaintext: str) -> tuple[bytes, bytes, bytes]:
    """Encrypt plaintext using a keystream derived from key and a random nonce.

    Returns (nonce, ciphertext, tag) where tag is HMAC-SHA256 over plaintext.
    """
    if isinstance(plaintext, str):
        plaintext_b = plaintext.encode("utf-8")
    else:
        plaintext_b = plaintext
    nonce = os.urandom(16)
    # Derive keystream using PBKDF2 with key as password and nonce as salt
    keystream = __import__("hashlib").pbkdf2_hmac("sha256", key, nonce, 100_000, dklen=len(plaintext_b))
    ciphertext = _xor_bytes(plaintext_b, keystream)
    tag = __import__("hmac").new(key, plaintext_b, __import__("hashlib").sha256).digest()
    return nonce, ciphertext, tag


def _decrypt_password(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> str:
    # Recompute keystream and xor to get plaintext, then verify tag
    keystream = __import__("hashlib").pbkdf2_hmac("sha256", key, nonce, 100_000, dklen=len(ciphertext))
    plaintext_b = _xor_bytes(ciphertext, keystream)
    expected_tag = __import__("hmac").new(key, plaintext_b, __import__("hashlib").sha256).digest()
    if not __import__("hmac").compare_digest(expected_tag, tag):
        raise ValueError("invalid tag")
    return plaintext_b.decode("utf-8")


def _hash_password(password: str, salt: bytes, iterations: int) -> bytes:
    """Derive a key from password using PBKDF2-HMAC-SHA256.

    Returns the derived key bytes.
    """
    if isinstance(password, str):
        password = password.encode("utf-8")
    return __import__("hashlib").pbkdf2_hmac("sha256", password, salt, iterations)


def verify_user(username: str, candidate_password: str) -> bool:
    """Verify a candidate password for username.

    Returns True if the password matches, False otherwise.
    """
    user_data_file = os.path.join("data", "passwords.json")
    if not os.path.exists(user_data_file):
        return False

    with open(user_data_file, "r", encoding="utf-8") as f:
        try:
            users = json.load(f)
        except json.JSONDecodeError:
            return False

    if not isinstance(users, dict):
        return False

    record = users.get(username)
    if not record:
        return False

    salt = bytes.fromhex(record["salt"])
    iterations = int(record.get("iterations", 100_000))
    expected = bytes.fromhex(record["hash"])

    candidate_dk = _hash_password(candidate_password, salt, iterations)

    # Constant-time comparison
    return __import__("hmac").compare_digest(candidate_dk, expected)


def main() -> None:
    """Entry point for the password manager.

    When run directly, this prints a greeting.  You will replace this
    with registration, login and menu functionality in future ships.
    """
    import argparse
    import getpass

    parser = argparse.ArgumentParser(prog="password_manager")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("register", help="Register a new user")

    add_cmd = sub.add_parser("add", help="Add a site password for a user")
    add_cmd.add_argument("username", help="Registered username")
    add_cmd.add_argument("site", help="Site name")
    add_cmd.add_argument("account_username", help="Account username for the site")

    list_cmd = sub.add_parser("list", help="List stored passwords for a user")
    list_cmd.add_argument("username", help="Registered username")

    args = parser.parse_args()

    if not args.cmd:
        print("Welcome to the Password Manager!")
        parser.print_help()
        return

    if args.cmd == "register":
        user = input("username: ")
        pw = getpass.getpass("master password: ")
        pm = None
        try:
            register_user(user, pw)
            print("User registered")
        except ValueError as e:
            print("Error:", e)

    elif args.cmd == "add":
        user = args.username
        site = args.site
        acct = args.account_username
        pw = getpass.getpass("master password: ")
        site_pw = getpass.getpass("site password: ")
        try:
            add_password_encrypted(site, user, site_pw, pw)
            print("Password added")
        except Exception as e:
            print("Error adding password:", e)

    elif args.cmd == "list":
        user = args.username
        pw = getpass.getpass("master password: ")
        try:
            items = get_passwords_encrypted(user, pw)
            if not items:
                print("No passwords stored")
            for it in items:
                print(f"{it['site']}: {it['username']} -> {it['password']}")
        except Exception as e:
            print("Error retrieving passwords:", e)


if __name__ == "__main__":
    main()