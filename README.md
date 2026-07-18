# Sikrypt

Sikrypt est une API de cryptographie educative. Le backend (Rust/Axum) expose :

- des endpoints modernes sous `/crypto/*` (base64 partout, rate limit, API key obligatoire)
- des endpoints pedagogiques pour apprendre les algorithmes classiques

Un front React/Vite minimal est fourni pour tester l API.

## Demarrage rapide

### Pre-requis

- Rust stable
- Node.js 18+ (front)

### Lancer le backend

```bash
cd backend
cargo run
```

### Lancer le front

```bash
cd front
npm install
npm run dev
```

## Docker

Lance la stack complete avec:

```bash
docker compose up --build
```

- Backend: `https://localhost:3000`
- Front: `http://localhost:8080`
- API key: utilise `SIKRYPT_API_KEY` si tu veux remplacer la valeur par defaut `changeme`

## Documentation

- OpenAPI JSON: `https://localhost:3000/openapi.json`
- Swagger UI: `https://localhost:3000/docs`

## Config rapide

### Backend

- `SIKRYPT_HOST` (defaut: `127.0.0.1`)
- `SIKRYPT_PORT` (defaut: `3000`)
- `SIKRYPT_API_KEY` (obligatoire, protege `/crypto/*`)
- `SIKRYPT_TLS_CERT_PATH` et `SIKRYPT_TLS_KEY_PATH` (optionnels, sinon un certificat auto-signe est genere)
- `SIKRYPT_REQUEST_TIMEOUT_MS` (defaut: `15000`)
- `SIKRYPT_CONCURRENCY_LIMIT` (defaut: `128`)
- `SIKRYPT_CORS_ORIGINS` (defaut: `http://localhost:5173,http://127.0.0.1:5173`)

### Front

- `VITE_API_BASE` (optionnel, defaut: `/api`)

Le secret `SIKRYPT_API_KEY` n'est plus injecte dans le bundle front. Il est ajoute au niveau du proxy Nginx ou du proxy Vite en dev.

```bash
VITE_API_BASE=/api
```

## Architecture rapide

- `backend/` : API Rust (Axum), routes, models, algorithms, tests
- `front/` : interface web minimale (React/Vite)
- `docs/` : notes d architecture

## Algorithmes (educatif)

- Asymetriques: Diffie-Hellman, ECC (courbes jouets), ElGamal, RSA
- Signatures: DSA, ECDSA (courbe jouet), ElGamal, RSA-PSS, RSA-PKCS#1 v1.5
- Hash: SHA-256, SHA-512, MD5, HMAC-SHA256
- Symetriques: AES-CBC, DES-CBC, RC4
- Classiques: Caesar, Vigenere, Hill, Playfair, Affine, OTP, Analyse
- Homomorphique: Paillier
- Secret sharing: Shamir
- Communications: Secure channel, Voting (demo)

## API moderne (/crypto)

- Generation de cles: X25519, Ed25519, RSA
- Secure channel: X25519 + HKDF-SHA256 + AES-256-GCM
- RSA-OAEP (encrypt/decrypt)
- Ed25519 (sign/verify)
- RSA-PSS (sign/verify)

## Tests

```bash
cd backend
cargo test
```

## Lire les README detailles

- Backend: [backend/README.md](backend/README.md)
- Front: [front/README.md](front/README.md)

## Limites educatives

Les endpoints pedagogiques sont destines a l apprentissage et aux demonstrations. Ils ne visent pas un usage production.

## Licence

Voir `LICENSE`.
