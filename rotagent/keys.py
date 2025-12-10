import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class KeyManager:
    @staticmethod
    def generate_rsa_keypair():
        """Generates RSA Keypair. Returns Private PEM (internal) and Public PEM (file)."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        public_pem = (
            private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
        )

        return private_pem, public_pem

    @staticmethod
    def load_public_keys(directory):
        """Scans directory for .pem/.pub files and maps filename->key."""
        key_map = {}
        if not os.path.exists(directory):
            print(f"⚠️  [OrchestratorCore] Keys directory missing: {directory}")
            return key_map

        for filename in os.listdir(directory):
            if filename.endswith((".pem", ".pub", ".key")):
                issuer_id = os.path.splitext(filename)[0]
                file_path = os.path.join(directory, filename)
                try:
                    with open(file_path, "r") as f:
                        content = f.read().strip()
                        if "-----BEGIN PUBLIC KEY-----" in content:
                            key_map[issuer_id] = content
                except Exception as e:
                    print(f"❌ Error loading {filename}: {e}")
        return key_map
