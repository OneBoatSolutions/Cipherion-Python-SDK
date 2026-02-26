"""
basic_example.py - Python 3 port of the basic CipherionClient usage example.
"""

import os
from datetime import datetime, timezone

from cipherion import CipherionClient, CipherionError, DeepEncryptOptions
from dotenv import load_dotenv
load_dotenv()
def basic_example() -> None:
    client = CipherionClient({
        "base_url":   os.environ.get("CIPHERION_BASE_URL"),
        "project_id": os.environ.get("CIPHERION_PROJECT_ID"),
        "api_key":    os.environ.get("CIPHERION_API_KEY"),
        "passphrase": os.environ.get("CIPHERION_PASSPHRASE"),
    })

    try:
        # Basic string encryption
        plaintext = "Hello, World!"
        encrypted = client.encrypt(plaintext)
        print("Encrypted:", encrypted)

        # Basic string decryption
        decrypted = client.decrypt(encrypted)
        print("Decrypted:", decrypted)

        # Deep object encryption
        user_data = {
            "user": {
                "name":  "John Doe",
                "email": "john@example.com",
                "ssn":   "123-45-6789",
            },
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version":   "1.0",
            },
        }

        deep_encrypted = client.deep_encrypt(user_data, DeepEncryptOptions( exclude_patterns=["version"]
    )
)
        print("Deep Encrypted:", deep_encrypted["encrypted"])

        # Deep object decryption
        deep_decrypted = client.deep_decrypt(deep_encrypted["encrypted"])
        print("Deep Decrypted:", deep_decrypted["data"])

    except CipherionError as error:
        print("Error:", error.message)


if __name__ == "__main__":
    basic_example()