import time
import uuid
import json
import hashlib
import jwt
import aiohttp


class OrchestratorClient:
    @staticmethod
    async def send_secure_request(session: aiohttp.ClientSession, url: str, payload: dict,
                                  issuer_id: str, private_key_pem: str):
        """
        Generates a JWT signed request and sends it via the provided aiohttp session.
        """
        json_body = json.dumps(payload, separators=(',', ':'))
        body_hash = hashlib.sha256(json_body.encode()).hexdigest()

        current_time = time.time()
        claims = {
            "iss": issuer_id,
            "iat": current_time,
            "exp": current_time + 60,
            "jti": uuid.uuid4().hex,
            "content_sha256": body_hash
        }

        token = jwt.encode(claims, private_key_pem, algorithm="RS256")
        headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'}

        try:
            async with session.post(f"{url}/agent", data=json_body, headers=headers, timeout=30) as response:
                if response.status == 200:
                    res_data = await response.json()
                    res_data['agent_url'] = url
                    return res_data

                # Handle standard error codes
                error_msg = 'Auth Failed' if response.status == 401 else \
                    'Replay Detected' if response.status == 429 else \
                        f"Status {response.status}"
                return {'error': error_msg, 'agent_url': url}
        except Exception as e:
            return {'error': str(e), 'agent_url': url}