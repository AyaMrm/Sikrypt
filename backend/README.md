# Sikrypt Backend

API de cryptographie educative ecrite en Rust (Axum). Le backend expose :

- des endpoints modernes sous `/crypto/*` (base64 partout, rate limit, API key obligatoire)
- des endpoints pedagogiques pour apprendre les algorithmes classiques et les bases crypto

Le front (dans `../front`) est volontairement minimal et sert de demo.

## Objectifs

- Offrir une base claire, testee et documentee pour l'apprentissage.
- Separer endpoints modernes et endpoints educatifs dans une meme API.

## Organisation

- `src/algorithms/` : implementations des algorithmes
- `src/routes/` : routes Axum par famille
- `src/models/` : schemas de requetes/reponses
- `tests/integration.rs` : tests d'integration HTTP

## Groupes d'endpoints

- Moderne: `/crypto/*`
- Educatif: `/asymmetric/*`, `/classic/*`, `/hash/*`, `/signature/*`, `/symmetric/*`, `/comms/*`

## Demo de communication (WebSocket + comms)

Le backend propose une demo de communication securisee:

- WebSocket: `/ws/secure`
- Endpoints REST: `/comms/*` (canal securise, vote demo)

Flux simplifie du chat securise (cote front):

1. Echange des cles publiques RSA via WebSocket.
2. Chiffrement d'une cle AES avec la cle publique du peer.
3. Envoi de messages chiffres en AES-GCM.

Ce flux est expose dans l'onglet "Secure Chat" du front.

## Conventions API

- Les donnees binaires sont en base64 (suffixe `_base64`).
- Reponses d'erreur (format commun):

```json
{ "error": "code", "message": "message" }
```

## Securite et limites

- API key obligatoire: `SIKRYPT_API_KEY` doit etre defini, et les routes `/crypto/*` exigent `x-api-key`.
- Rate limit: applique sur `/crypto/*` (par API key et par IP).
- Limite de taille du body: 64 KB (globale).

## Demarrage rapide

### Pre-requis

- Rust stable

### Lancer le serveur

```bash
cd backend
cargo run
```

Le serveur ecoute par defaut sur `http://127.0.0.1:3000`.

### Variables d'environnement

- `SIKRYPT_HOST` (defaut: `127.0.0.1`)
- `SIKRYPT_PORT` (defaut: `3000`)
- `SIKRYPT_API_KEY` (obligatoire, protege `/crypto/*`)
- `SIKRYPT_REQUEST_TIMEOUT_MS` (defaut: `15000`)
- `SIKRYPT_CONCURRENCY_LIMIT` (defaut: `128`)
- `SIKRYPT_CORS_ORIGINS` (defaut: `http://localhost:5173,http://127.0.0.1:5173`)

## Docs API

- OpenAPI JSON: `http://127.0.0.1:3000/openapi.json`
- Swagger UI: `http://127.0.0.1:3000/docs`

## Exemples cURL (moderne)

### Generer une paire X25519

```bash
curl -s -X POST http://127.0.0.1:3000/crypto/keys/x25519
```

### Secure channel: chiffrer

```bash
curl -s -X POST http://127.0.0.1:3000/crypto/secure-channel/encrypt \
  -H "content-type: application/json" \
  -d '{
    "sender_private_key_base64": "<BASE64>",
    "receiver_public_key_base64": "<BASE64>",
    "plaintext_base64": "<BASE64>",
    "aad_base64": "<BASE64>"
  }'
```

### Secure channel: dechiffrer

```bash
curl -s -X POST http://127.0.0.1:3000/crypto/secure-channel/decrypt \
  -H "content-type: application/json" \
  -d '{
    "receiver_private_key_base64": "<BASE64>",
    "sender_public_key_base64": "<BASE64>",
    "salt_base64": "<BASE64>",
    "nonce_base64": "<BASE64>",
    "ciphertext_base64": "<BASE64>",
    "aad_base64": "<BASE64>"
  }'
```

### RSA OAEP: chiffrer

```bash
curl -s -X POST http://127.0.0.1:3000/crypto/rsa/oaep/encrypt \
  -H "content-type: application/json" \
  -d '{
    "public_key_pem": "<PEM>",
    "plaintext_base64": "<BASE64>",
    "label_base64": "<BASE64>"
  }'
```

### Ed25519: signer/verifier

```bash
curl -s -X POST http://127.0.0.1:3000/crypto/ed25519/sign \
  -H "content-type: application/json" \
  -d '{
    "private_key_base64": "<BASE64>",
    "message_base64": "<BASE64>"
  }'
```

```bash
curl -s -X POST http://127.0.0.1:3000/crypto/ed25519/verify \
  -H "content-type: application/json" \
  -d '{
    "public_key_base64": "<BASE64>",
    "message_base64": "<BASE64>",
    "signature_base64": "<BASE64>"
  }'
```

## Exemples cURL (educatif)

### Caesar (encrypt)

```bash
curl -s -X POST http://127.0.0.1:3000/classic/caesar/encrypt \
  -H "content-type: application/json" \
  -d '{ "text": "HELLO", "shift": 3 }'
```

### Vigenere (estimate key length)

```bash
curl -s -X POST http://127.0.0.1:3000/classic/vigenere/estimate-key-length \
  -H "content-type: application/json" \
  -d '{ "text": "ATTACKATDAWN", "max_key_len": 12 }'
```

### HMAC SHA-256

```bash
curl -s -X POST http://127.0.0.1:3000/hash/hmac \
  -H "content-type: application/json" \
  -d '{
    "key_base64": "<BASE64>",
    "message_base64": "<BASE64>"
  }'
```

## Tests

```bash
cargo test
```

## Notes educatives

Les endpoints educatifs sont destines a l'apprentissage et aux demonstrations. Ils ne visent pas un usage production.
