# src/encryption/vault.py
import os
import base64
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SimpleVault:
    """
    Mô phỏng envelope encryption pattern (thay thế AWS KMS cho local dev).

    Architecture:
        Master Key (KEK) → encrypts → Data Key (DEK) → encrypts → Data
    """

    def __init__(self, master_key_path: str = ".vault_key"):
        self.master_key_path = master_key_path
        self.kek = self._load_or_create_kek()

    def _load_or_create_kek(self) -> bytes:
        """
        Load KEK từ file nếu tồn tại,
        ngược lại generate 32-byte random key và lưu vào file.
        QUAN TRỌNG: Trong production, KEK phải lưu trong HSM/KMS, không phải file.
        """
        if os.path.exists(self.master_key_path):
            with open(self.master_key_path, "rb") as f:
                return base64.b64decode(f.read())
        else:
            kek = os.urandom(32)  # 256-bit key
            with open(self.master_key_path, "wb") as f:
                f.write(base64.b64encode(kek))
            return kek

    def generate_dek(self) -> tuple[bytes, bytes]:
        """
        Generate một Data Encryption Key (DEK) mới.
        Trả về (plaintext_dek, encrypted_dek).
        Dùng AESGCM để encrypt DEK bằng KEK.
        """
        plaintext_dek = os.urandom(32)

        # Encrypt DEK bằng KEK
        aesgcm = AESGCM(self.kek)
        nonce = os.urandom(12)
        encrypted_dek = nonce + aesgcm.encrypt(nonce, plaintext_dek, None)

        return plaintext_dek, encrypted_dek

    def decrypt_dek(self, encrypted_dek: bytes) -> bytes:
        """
        Decrypt encrypted DEK bằng KEK.
        Trả về plaintext DEK.
        """
        nonce = encrypted_dek[:12]
        ciphertext = encrypted_dek[12:]
        aesgcm = AESGCM(self.kek)
        return aesgcm.decrypt(nonce, ciphertext, None)

    def encrypt_data(self, plaintext: str) -> dict:
        """
        Implement envelope encryption.
        1. Generate DEK mới
        2. Encrypt data bằng plaintext DEK
        3. Xóa plaintext DEK khỏi memory
        4. Trả về dict chứa encrypted_dek và ciphertext (base64 encoded)

        Return format:
        {
            "encrypted_dek": "<base64>",
            "ciphertext": "<base64>",
            "algorithm": "AES-256-GCM"
        }
        """
        plaintext_dek, encrypted_dek = self.generate_dek()

        # Encrypt data bằng plaintext DEK
        aesgcm = AESGCM(plaintext_dek)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

        # Xóa plaintext DEK
        del plaintext_dek

        return {
            "encrypted_dek": base64.b64encode(encrypted_dek).decode(),
            "ciphertext": base64.b64encode(nonce + ciphertext).decode(),
            "algorithm": "AES-256-GCM"
        }

    def decrypt_data(self, encrypted_payload: dict) -> str:
        """
        Decrypt data từ envelope encryption payload.
        1. Decrypt DEK bằng KEK
        2. Decrypt data bằng DEK
        3. Trả về plaintext string
        """
        encrypted_dek = base64.b64decode(encrypted_payload["encrypted_dek"])
        ciphertext_with_nonce = base64.b64decode(encrypted_payload["ciphertext"])

        # Decrypt DEK bằng KEK
        plaintext_dek = self.decrypt_dek(encrypted_dek)
        nonce = ciphertext_with_nonce[:12]
        ciphertext = ciphertext_with_nonce[12:]

        aesgcm = AESGCM(plaintext_dek)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        del plaintext_dek

        return plaintext.decode("utf-8")

    def encrypt_column(self, df, column: str) -> "pd.DataFrame":
        """
        Encrypt một cột trong DataFrame.
        Thay thế giá trị gốc bằng JSON string của encrypted payload.
        """
        import pandas as pd
        df = df.copy()
        df[column] = df[column].apply(
            lambda x: json.dumps(self.encrypt_data(str(x)))
        )
        return df
