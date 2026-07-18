# Sikrypt Front

Interface web pour tester et expliquer les algorithmes cryptographiques exposes par le backend.
Le front est un client Vite + React qui consomme l'API REST et la demo WebSocket.

## Objectifs

- Fournir une UI simple pour manipuler les endpoints educatifs et modernes.
- Rendre visibles les entrees/sorties (JSON, base64, hex) pour l'apprentissage.
- Proposer une demo de communication securisee via WebSocket.

## Fonctionnalites principales

- Classiques: Caesar, Vigenere, Affine, Playfair, Hill, OTP
- Symetriques: RC4, DES, AES, Rijndael, Twofish, Serpent, RC6
- Asymetriques: RSA-OAEP, Diffie-Hellman, ElGamal, ECDH P-256
- Signatures: RSA-PSS, RSA PKCS#1 v1.5, DSA, ECDSA, ElGamal
- Hash: MD5, SHA-256, SHA-512, HMAC-SHA256
- Secure Chat: demo de communication avec negotiation de cle et chiffrement

## Prerequis

- Node.js 18+

## Demarrage rapide

```bash
cd front
npm install
npm run dev
```

Le front est accessible sur `http://127.0.0.1:5173`.

## Docker

Le front peut etre servi via Nginx dans la stack Docker racine.

```bash
docker compose up --build
```

Il sera accessible sur `http://localhost:8080` et pointera vers le backend en `https://localhost:3000`.

## Configuration

Le front parle au backend via un proxy local sur `/api` et `/ws/secure`.
En mode dev, Vite relaie les requetes vers `https://localhost:3000`.
En Docker, Nginx fait le relais vers le service backend.

La seule variable utile au front est:

- `VITE_API_BASE` (optionnelle, defaut: `/api`)

Le secret `SIKRYPT_API_KEY` reste cote serveur/proxy et n'est plus injecte dans le bundle React.
En local, exporte `SIKRYPT_API_KEY` avant de lancer `npm run dev` pour que le proxy Vite ajoute bien l'en-tete.

## Demo communication securisee

Le panneau "Secure Chat" fait une demo WebSocket:

- Connexion a `wss://<backend>/ws/secure`
- Le front utilise le meme chemin `/ws/secure`, proxifie en dev et en Docker
- Echange de cles RSA (partage de cle publique)
- Chiffrement d'une cle AES avec RSA
- Chiffrement des messages en AES-GCM

Assure-toi que le backend est lance avant d'ouvrir cette section.

## Notes

- Les champs `*_base64` attendent du base64 valide.
- Les champs `*_hex` attendent de l'hex (longueur paire).
- Les entrees sont volontairement simples pour la lisibilite.
