import os

# from cipherion import CipherionClient, CipherionError


# client = CipherionClient({
#         "base_url":   os.environ.get("CIPHERION_BASE_URL"),
#         "project_id": os.environ.get("CIPHERION_PROJECT_ID"),
#         "api_key":    os.environ.get("CIPHERION_API_KEY"),
#         "passphrase": os.environ.get("CIPHERION_PASSPHRASE"),
#     })
# # config picked from env vars
# def encrypt_string():
#     try:
#         plaintext = "Hello, World!"
#         encrypted = client.encrypt(plaintext)
#         print(encrypted)

#     except CipherionError as error:
#         print("Error:", error.message)


# if __name__ == "__main__":
#     encrypt_string()

from cipherion import CipherionClient, CipherionError

client = CipherionClient({
         "base_url":   os.environ.get("CIPHERION_BASE_URL"),
         "project_id": os.environ.get("CIPHERION_PROJECT_ID"),
         "api_key":    os.environ.get("CIPHERION_API_KEY"),
         "passphrase": os.environ.get("CIPHERION_PASSPHRASE"),
     })  # config from env vars

def encrypt_password(password: str) -> dict:
    try:
        encrypted = client.encrypt(password)
        return {
            "success": True,
            "encryptedPassword": encrypted,
        }
    except CipherionError as error:
        print("Password encryption failed:", error.message)
        raise


# Usage
result = encrypt_password("MySecurePass123!")
print(result)