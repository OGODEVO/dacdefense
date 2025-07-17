
from langflow.custom import Component
from langflow.io import Input, Output
from langflow.schema import Data
from cryptography.fernet import Fernet

class CryptoUtils(Component):
    display_name = "Crypto Utils"
    description = "Encrypts and decrypts data."
    icon = "lock"

    inputs = [
        Input(name="data_to_encrypt", display_name="Data to Encrypt", required=True),
        Input(name="key", display_name="Encryption Key", required=True)
    ]

    outputs = [
        Output(display_name="Encrypted Data", name="encrypted_data", method="encrypt_data")
    ]

    def encrypt_data(self) -> Data:
        f = Fernet(self.key.encode())
        encrypted_data = f.encrypt(self.data_to_encrypt.encode())
        return Data(data={"encrypted_data": encrypted_data.decode()})
