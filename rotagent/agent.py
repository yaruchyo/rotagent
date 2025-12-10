import os
import time
import hashlib
import jwt
from functools import wraps
from flask import request, jsonify
from .keys import KeyManager


class AgentAuth:
    def __init__(self, keys_dir=None, dev_mode=None):
        """
        Initialize Agent Authorization.

        :param keys_dir: Path to keys folder. Defaults to './authorized_keys'
        :param dev_mode: Boolean. If None, checks os.getenv('APP_ENV') == 'development'
        """
        # 1. Default Logic for Keys Directory
        if keys_dir is None:
            # Defaults to 'authorized_keys' in the current running directory
            self.keys_dir = os.path.join(os.getcwd(), "authorized_keys")
        else:
            self.keys_dir = keys_dir

        # 2. Default Logic for Dev Mode
        if dev_mode is None:
            # automatically check environment variable
            self.dev_mode = os.getenv("APP_ENV", "production") == "development"
        else:
            self.dev_mode = dev_mode

        self.replay_cache = {}

        # Load keys immediately
        self.trusted_keys = KeyManager.load_public_keys(self.keys_dir)

        # Debug output to help user confirm settings
        mode_str = "DEVELOPMENT (Insecure)" if self.dev_mode else "PRODUCTION (Secure)"
        print(f"🛡️  [AgentAuth] Mode: {mode_str}")
        print(f"🛡️  [AgentAuth] Keys Directory: {self.keys_dir}")
        print(f"🛡️  [AgentAuth] Loaded {len(self.trusted_keys)} trusted issuers.")

    def _clean_replay_cache(self):
        now = time.time()
        expired = [jti for jti, exp in self.replay_cache.items() if exp < now]
        for jti in expired:
            del self.replay_cache[jti]

    def require_auth(self, f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return jsonify({"error": "Missing/Invalid Authorization header"}), 401

            token = auth_header.split(" ")[1]

            try:
                # 1. Identify Issuer
                unverified = jwt.decode(token, options={"verify_signature": False})
                issuer = unverified.get("iss")

                if issuer not in self.trusted_keys:
                    # Hot-reload check in case user dropped a file while running
                    self.trusted_keys = KeyManager.load_public_keys(self.keys_dir)
                    if issuer not in self.trusted_keys:
                        return jsonify({"error": f"Unknown Issuer: {issuer}"}), 401

                public_key = self.trusted_keys[issuer]

                # 2. Verify Signature
                payload = jwt.decode(token, public_key, algorithms=["RS256"])

                # 3. Security Checks (Skip in Dev)
                if not self.dev_mode:
                    jti = payload.get("jti")
                    exp = payload.get("exp")

                    if not jti or not exp:
                        return jsonify({"error": "Invalid Claims"}), 401

                    self._clean_replay_cache()
                    if jti in self.replay_cache:
                        return jsonify({"error": "Replay Detected"}), 429
                    self.replay_cache[jti] = exp

                    # Integrity Check
                    received_hash = hashlib.sha256(request.get_data()).hexdigest()
                    if received_hash != payload.get("content_sha256"):
                        return jsonify({"error": "Body Tampering Detected"}), 401

            except jwt.ExpiredSignatureError:
                return jsonify({"error": "Token Expired"}), 401
            except Exception as e:
                return jsonify({"error": str(e)}), 401

            return f(*args, **kwargs)

        return decorated
