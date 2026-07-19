# Sikrypt

Sikrypt is a demonstration application focused on modern and educational cryptography. It combines a Rust backend API with a React/Vite web interface to explore encryption, hashing, signing, and secure communication algorithms.

## Overview

The project has two main goals:

- provide a clear and testable API for learning cryptography through practice;
- offer an interactive interface to visualize operations and algorithm results.

## Main Features

### Modern API

The API exposes routes under the /crypto prefix for more realistic and secure operations, including:

- key generation: X25519, Ed25519, RSA;
- secure channel: X25519 + HKDF-SHA256 + AES-256-GCM;
- RSA-OAEP: encryption/decryption;
- Ed25519: signing/verification;
- RSA-PSS: signing/verification.

### Educational Algorithms

The backend also provides educational endpoints to discover classic algorithms and cryptography basics:

- classic: Caesar, Vigenère, Hill, Playfair, Affine, OTP;
- symmetric: AES-CBC, DES-CBC, RC4;
- asymmetric: Diffie-Hellman, ElGamal, RSA;
- signatures: DSA, ECDSA, ElGamal, RSA PKCS#1 v1.5, RSA-PSS;
- hash: SHA-256, SHA-512, MD5, HMAC-SHA256;
- homomorphic: Paillier;
- secret sharing: Shamir;
- communications: secure channel and voting demos.

### Web Interface

The frontend provides a simple UI to test endpoints, inspect inputs and outputs, and try the secure WebSocket chat demo.

## Repository Structure

- backend/: Rust API (Axum), routes, models, algorithms, tests;
- front/: React/Vite web interface;
- docs/: architecture notes;
- docker-compose.yml: local stack orchestration;
- package.json: root-level validation scripts.

## Prerequisites

- Stable Rust;
- Node.js 18+;
- Docker Desktop (optional, for the full stack).

## Quick Start

### 1. Start the backend

```bash
cd backend
cargo run
```

The backend listens by default on https://localhost:3000.

### 2. Start the frontend

```bash
cd front
npm install
npm run dev
```

The frontend is then available at http://localhost:5173.

### 3. Start with Docker

From the project root:

```bash
docker compose up --build
```

- Backend: https://localhost:3000
- Frontend: http://localhost:8080

## Configuration

### Backend environment variables

- SIKRYPT_HOST: listening host (default: 127.0.0.1);
- SIKRYPT_PORT: listening port (default: 3000);
- SIKRYPT_API_KEY: required key to protect /crypto routes;
- SIKRYPT_TLS_CERT_PATH and SIKRYPT_TLS_KEY_PATH: paths to a custom TLS certificate;
- SIKRYPT_REQUEST_TIMEOUT_MS: request timeout;
- SIKRYPT_CONCURRENCY_LIMIT: concurrency limit;
- SIKRYPT_CORS_ORIGINS: allowed CORS origins.

### Frontend environment variables

- VITE_API_BASE: API base URL used by the frontend (default: /api).

> The SIKRYPT_API_KEY secret is not injected into the frontend bundle. It must be handled on the server or proxy side.

## API Documentation

When the backend is running, you can consult:

- OpenAPI JSON: https://localhost:3000/openapi.json
- Swagger UI: https://localhost:3000/docs

## Quick Examples

### Generate an X25519 key pair

```bash
curl -k -s -X POST https://localhost:3000/crypto/keys/x25519
```

### Encrypt a message with RSA-OAEP

```bash
curl -k -s -X POST https://localhost:3000/crypto/rsa/oaep/encrypt \
  -H "content-type: application/json" \
  -d '{
    "public_key_pem": "<PEM>",
    "plaintext_base64": "<BASE64>",
    "label_base64": "<BASE64>"
  }'
```

### Test a classic algorithm

```bash
curl -k -s -X POST https://localhost:3000/classic/caesar/encrypt \
  -H "content-type: application/json" \
  -d '{"text":"HELLO","shift":3}'
```

## Tests

### Backend

```bash
cargo test --manifest-path backend/Cargo.toml
```

### Frontend

```bash
npm --prefix front test
```

### Global validation

```bash
npm test
```

## Important Notes

- The /crypto routes require a valid API key.
- Binary data is typically transmitted as base64.
- Educational endpoints are intended for learning and demonstration, not for production use.

## License

See the LICENSE file.
