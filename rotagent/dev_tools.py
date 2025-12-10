import os
import json
import base64
import hashlib
import time
import uuid
import jwt
from dotenv import load_dotenv
from cryptography.hazmat.primitives import serialization
from .keys import KeyManager


class DevTools:
    @staticmethod
    def setup_persistent_keys(keys_dir="authorized_keys", issuer_id="dev_postman"):
        """
        Generates keys, saves the public key to disk, and prints the private key
        formatted for the .env file.
        """
        print(f"⚙️  Setting up Development Keys for issuer: '{issuer_id}'...")

        # 1. Create directory
        if not os.path.exists(keys_dir):
            os.makedirs(keys_dir)
            print(f"   > Created directory: {keys_dir}/")

        # 2. Generate Pair (Using our existing KeyManager)
        private_pem, public_pem = KeyManager.generate_rsa_keypair()

        # 3. Save Public Key
        public_key_path = os.path.join(keys_dir, f"{issuer_id}.pem")
        with open(public_key_path, "w") as f:
            f.write(public_pem)

        print(f"   > ✅ Created Public Key file: {public_key_path}")

        # 4. Format Private Key for .env (Base64 encoded to fit one line)
        # Convert PEM string back to bytes for b64 encoding
        b64_private = base64.b64encode(private_pem.encode("utf-8")).decode("utf-8")

        print("\n" + "=" * 60)
        print("ACTION REQUIRED: UPDATE YOUR .ENV FILE")
        print("=" * 60)
        print("Copy the line below and paste it into your .env file:")
        print("-" * 20)
        print(f"DEV_PRIVATE_KEY={b64_private}")
        print("-" * 20)
        print(f"(Key allows signing requests as '{issuer_id}')")

    @staticmethod
    def generate_bearer_token(query, env_var="DEV_PRIVATE_KEY", issuer_id="dev_postman"):
        """
        Loads the private key from .env and generates a signed JWT for the given query.
        """
        load_dotenv()
        b64_private_key = os.getenv(env_var)

        if not b64_private_key:
            print(f"❌ Error: '{env_var}' not found in .env.")
            print("   Please run your setup_keys script first.")
            return

        try:
            # Decode Base64 back to PEM bytes
            private_key_bytes = base64.b64decode(b64_private_key)

            # Load private key object
            private_key = serialization.load_pem_private_key(private_key_bytes, password=None)
        except Exception as e:
            print(f"❌ Error decoding private key: {e}")
            return

        # Prepare Payload
        body_data = {"query": query}
        # Separators removes spaces for consistent hashing
        json_body = json.dumps(body_data, separators=(",", ":"))
        body_hash = hashlib.sha256(json_body.encode()).hexdigest()

        # Create Token
        current_time = time.time()
        claims = {
            "iss": issuer_id,
            "iat": current_time,
            "exp": current_time + (6 * 3600),  # 6 hours
            "jti": uuid.uuid4().hex,
            "content_sha256": body_hash,
        }

        token = jwt.encode(claims, private_key, algorithm="RS256")

        print(f"\n✅ Generated Fresh Token for Issuer: {issuer_id}")
        print("-" * 60)
        print("1. Set Request Type to: POST")
        print("2. Body (Raw JSON):")
        print(json_body)
        print("-" * 60)
        print("3. Authorization (Bearer Token):")
        print(token)
        print("-" * 60)

        return token, json_body
