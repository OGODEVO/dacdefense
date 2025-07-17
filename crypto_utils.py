from cryptography.fernet import Fernet

# Generate a key for encryption and decryption
# In a real application, you would want to store this key securely
key = Fernet.generate_key()
fernet = Fernet(key)

def encrypt_message(message: str) -> bytes:
    """Encrypts a message."""
    return fernet.encrypt(message.encode())

def decrypt_message(encrypted_message: bytes) -> str:
    """Decrypts a message."""
    return fernet.decrypt(encrypted_message).decode()
