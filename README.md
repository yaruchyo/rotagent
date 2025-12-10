<p align="center">
  <img src="https://img.shields.io/pypi/v/rotagent?style=for-the-badge&logo=pypi&logoColor=white" alt="PyPI Version"/>
  <img src="https://img.shields.io/pypi/pyversions/rotagent?style=for-the-badge&logo=python&logoColor=white" alt="Python Versions"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"/>
</p>

<h1 align="center">🔐 rotagent</h1>

<p align="center">
  <strong>Secure Agent-Orchestrator Communication</strong><br/>
  <em>JWT-based authentication library for multi-agent AI systems</em>
</p>

<p align="center">
  <a href="https://pypi.org/project/rotagent/">📦 PyPI</a> •
  <a href="https://www.oqtopus.dev">🐙 oqtopus Platform</a> •
  <a href="#installation">🚀 Installation</a> •
  <a href="#quick-start">⚡ Quick Start</a>
</p>

---

## 🎯 What is rotagent?

**rotagent** is a Python library that provides secure communication between AI agents and orchestrators using JWT-based authentication with RSA keypairs. It's designed for distributed multi-agent systems where:

- **Orchestrators** need to securely call agent endpoints
- **Agents** need to verify the authenticity of incoming requests
- **Both** need protection against replay attacks and request tampering

## 🏗️ Architecture

rotagent sits between orchestrators (like [oqtopus](https://www.oqtopus.dev)) and specialized agents:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            ORCHESTRATOR                                  │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  from rotagent import KeyManager, OrchestratorClient              │  │
│  │                                                                    │  │
│  │  # Generate RSA keypair for new agent                             │  │
│  │  private_pem, public_pem = KeyManager.generate_rsa_keypair()      │  │
│  │                                                                    │  │
│  │  # Send signed request to agent                                   │  │
│  │  await OrchestratorClient.send_secure_request(...)                │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                         JWT-Signed Request
                        (RS256, SHA256 body hash)
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                               AGENT                                      │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │  from rotagent import AgentAuth                                    │  │
│  │                                                                    │  │
│  │  auth = AgentAuth()                                               │  │
│  │                                                                    │  │
│  │  @app.route("/agent", methods=["POST"])                           │  │
│  │  @auth.require_auth  # ← Verifies JWT signature & claims          │  │
│  │  def agent_endpoint():                                            │  │
│  │      ...                                                          │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

## 📦 Installation

```bash
pip install rotagent==0.1.0
```

## ⚡ Quick Start

### Agent Side (Flask Application)

Protect your agent endpoint with JWT verification:

```python
from flask import Flask, request, jsonify
from rotagent import AgentAuth

app = Flask(__name__)
auth = AgentAuth()  # Loads keys from ./authorized_keys/

@app.route("/agent", methods=["POST"])
@auth.require_auth  # ← Verifies JWT before allowing access
def agent_endpoint():
    data = request.get_json()
    query = data.get("query")
    
    # Your agent logic here
    result = process_query(query)
    
    return jsonify({"result": result})

if __name__ == "__main__":
    app.run(port=5001)
```

### Orchestrator Side

Send authenticated requests to agents:

```python
import aiohttp
from rotagent import OrchestratorClient, KeyManager

# Generate keypair (typically done once during agent registration)
private_pem, public_pem = KeyManager.generate_rsa_keypair()
# Save public_pem to agent's authorized_keys folder

async def call_agent():
    async with aiohttp.ClientSession() as session:
        response = await OrchestratorClient.send_secure_request(
            session=session,
            url="http://agent-server.com",
            payload={"query": "What movies are playing?"},
            issuer_id="my_orchestrator",
            private_key_pem=private_pem
        )
        return response
```

## 🛠️ Components

### `AgentAuth` — Protect Agent Endpoints

A Flask decorator that verifies incoming JWT tokens:

```python
from rotagent import AgentAuth

# Default: Auto-detect mode from APP_ENV environment variable
auth = AgentAuth()

# Explicit configuration
auth = AgentAuth(
    keys_dir="./authorized_keys",  # Where public keys are stored
    dev_mode=True                   # Disable security checks for testing
)

# Use as decorator
@app.route("/agent", methods=["POST"])
@auth.require_auth
def protected_endpoint():
    return jsonify({"status": "authenticated"})
```

**Security Features:**
| Feature | Development Mode | Production Mode |
|---------|------------------|-----------------|
| JWT Signature Verification | ✅ | ✅ |
| Token Expiration Check | ✅ | ✅ |
| Replay Attack Protection (JTI) | ❌ | ✅ |
| Body Tampering Detection | ❌ | ✅ |

### `OrchestratorClient` — Send Signed Requests

An async client for orchestrators to call agent endpoints:

```python
from rotagent import OrchestratorClient

response = await OrchestratorClient.send_secure_request(
    session=aiohttp_session,
    url="http://agent.example.com",
    payload={"query": "Your question here"},
    issuer_id="orchestrator_id",      # Identifies the caller
    private_key_pem=private_key_str   # RSA private key (PEM format)
)
```

**JWT Claims Generated:**
- `iss`: Issuer ID (orchestrator identifier)
- `iat`: Issued at timestamp
- `exp`: Expiration (60 seconds)
- `jti`: Unique token ID (prevents replay)
- `content_sha256`: Hash of request body (prevents tampering)

### `KeyManager` — RSA Key Operations

Generate and load RSA keypairs:

```python
from rotagent import KeyManager

# Generate new keypair
private_pem, public_pem = KeyManager.generate_rsa_keypair()
# Returns: (str, str) - PEM-encoded private and public keys

# Load public keys from directory
keys = KeyManager.load_public_keys("./authorized_keys")
# Returns: {"issuer_id": public_key_object, ...}
```

### `DevTools` — Development Utilities

Tools for local development and testing:

```python
from rotagent import DevTools

# Generate persistent development keys
# Creates: authorized_keys/dev_postman.pem
# Prints: DEV_PRIVATE_KEY=... (for .env file)
DevTools.setup_persistent_keys(
    keys_dir="authorized_keys",
    issuer_id="dev_postman"
)

# Generate a test token for Postman/curl
token, body = DevTools.generate_bearer_token(
    query="What are the best action movies?",
    env_var="DEV_PRIVATE_KEY",    # .env variable name
    issuer_id="dev_postman"
)

# Use the token in curl:
# curl -X POST http://localhost:5001/agent \
#   -H "Authorization: Bearer $token" \
#   -H "Content-Type: application/json" \
#   -d "$body"
```

## 🔒 Security Model

### Authentication Flow

```
1. REGISTRATION (One-time)
   ┌──────────────┐                     ┌──────────────┐
   │ Orchestrator │                     │    Agent     │
   └──────┬───────┘                     └──────┬───────┘
          │                                    │
          │  Generate RSA Keypair              │
          │  (KeyManager.generate_rsa_keypair) │
          │                                    │
          │  ─────── public_key.pem ─────────► │
          │                                    │
          │                     Save to authorized_keys/
          │                                    │

2. REQUEST (Every call)
   ┌──────────────┐                     ┌──────────────┐
   │ Orchestrator │                     │    Agent     │
   └──────┬───────┘                     └──────┬───────┘
          │                                    │
          │  Create JWT with claims:           │
          │  - iss: "orchestrator_id"          │
          │  - exp: now + 60s                  │
          │  - jti: unique_id                  │
          │  - content_sha256: body_hash       │
          │                                    │
          │  Sign with private key (RS256)     │
          │                                    │
          │  ═══════ POST /agent ═══════════►  │
          │  Header: Authorization: Bearer JWT │
          │  Body: {"query": "..."}            │
          │                                    │
          │                     Extract iss from JWT
          │                     Load public key for iss
          │                     Verify signature
          │                     Check exp, jti, sha256
          │                                    │
          │  ◄═══════ Response ════════════════│
          │                                    │
```

### Error Codes

| HTTP Status | Error | Meaning |
|-------------|-------|---------|
| 401 | Missing/Invalid Authorization header | No Bearer token provided |
| 401 | Unknown Issuer: {issuer} | No public key for this orchestrator |
| 401 | Token Expired | JWT exp claim in the past |
| 401 | Invalid Claims | Missing jti/exp in production mode |
| 401 | Body Tampering Detected | SHA256 mismatch (production only) |
| 429 | Replay Detected | Duplicate jti (production only) |

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ENV` | `production` | Set to `development` to disable security checks |

### Directory Structure

```
your_agent/
├── app.py
├── authorized_keys/           # Public keys from trusted orchestrators
│   ├── orchestrator_1.pem
│   ├── orchestrator_2.pem
│   └── dev_postman.pem        # Development key (generated by DevTools)
└── .env                       # DEV_PRIVATE_KEY for testing
```

## 🌐 Integration with oqtopus

rotagent is the authentication backbone for the [oqtopus](https://www.oqtopus.dev) orchestration platform:

1. **Register your agent** at [www.oqtopus.dev](https://www.oqtopus.dev)
2. **Download the `.pem` file** provided after registration
3. **Place it in `authorized_keys/`** in your agent's directory
4. **Use `@auth.require_auth`** on your `/agent` endpoint

oqtopus will then be able to securely route queries to your agent.

## 📋 API Reference

### `AgentAuth`

```python
class AgentAuth:
    def __init__(
        self,
        keys_dir: str = None,      # Default: ./authorized_keys
        dev_mode: bool = None       # Default: APP_ENV != 'production'
    )
    
    def require_auth(self, f: Callable) -> Callable:
        """Decorator to protect Flask endpoints"""
```

### `OrchestratorClient`

```python
class OrchestratorClient:
    @staticmethod
    async def send_secure_request(
        session: aiohttp.ClientSession,
        url: str,                   # Agent base URL
        payload: dict,              # Request body
        issuer_id: str,             # Your orchestrator ID
        private_key_pem: str        # PEM-encoded RSA private key
    ) -> dict:
        """Send authenticated request to agent's /agent endpoint"""
```

### `KeyManager`

```python
class KeyManager:
    @staticmethod
    def generate_rsa_keypair() -> Tuple[str, str]:
        """Generate (private_pem, public_pem) keypair"""
    
    @staticmethod
    def load_public_keys(keys_dir: str) -> Dict[str, RSAPublicKey]:
        """Load all .pem files from directory"""
```

### `DevTools`

```python
class DevTools:
    @staticmethod
    def setup_persistent_keys(
        keys_dir: str = "authorized_keys",
        issuer_id: str = "dev_postman"
    ) -> None:
        """Generate and save development keys"""
    
    @staticmethod
    def generate_bearer_token(
        query: str,
        env_var: str = "DEV_PRIVATE_KEY",
        issuer_id: str = "dev_postman"
    ) -> Tuple[str, str]:
        """Generate (token, body) for testing"""
```

## 🔗 Related Projects

| Project | Description |
|---------|-------------|
| [oqtopus](https://www.oqtopus.dev) | AI Agent Orchestration Platform |
| [example-agent](https://github.com/yaruchyo/example-agent) | Sample agent implementation |

## 📝 License

MIT License - See [LICENSE](LICENSE) for details.

## 🤝 Contributing

Contributions welcome! Areas of interest:

- Additional authentication strategies
- WebSocket support
- Language ports (Node.js, Go, etc.)

---

<p align="center">
  <strong>🔐 rotagent</strong> — <em>Secure your multi-agent AI systems.</em><br/>
  <a href="https://pypi.org/project/rotagent/">pip install rotagent</a>
</p>
