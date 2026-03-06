import asyncio
from cipherion import AsyncCipherionClient, DeepEncryptOptions, DeepDecryptOptions
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

async def main():

    # Initialize client
    client = AsyncCipherionClient()

    print("\n--- BASIC ENCRYPT / DECRYPT ---")

    # Simple encryption
    text = "hello world"

    encrypted = await client.encrypt(text)
    print("Encrypted:", encrypted)

    decrypted = await client.decrypt(encrypted)
    print("Decrypted:", decrypted)


    print("\n--- DEEP ENCRYPT / DEEP DECRYPT ---")

    # Structured data
    data = [
        {"name": "Alice", "salary": 50000},
        {"name": "Bob", "salary": 60000},
        {"name": "Charlie", "salary": 70000},
    ]

    # Deep encrypt
    deep_encrypted = await client.deep_encrypt(data, DeepEncryptOptions(exclude_fields = ["*name"]))
    print("Deep Encrypted:", deep_encrypted)

    # Deep decrypt
    deep_decrypted = await client.deep_decrypt(deep_encrypted["encrypted"], DeepDecryptOptions(exclude_fields = ["*name"]))
    print("Deep Decrypted:", deep_decrypted)
    await client.close()

# Run async function
asyncio.run(main())