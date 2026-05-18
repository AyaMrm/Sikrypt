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

## Configuration

Le front utilise l'URL du backend via la variable d'environnement suivante:

- `VITE_API_BASE` (defaut: `http://127.0.0.1:3000`)

Exemple d'un fichier `.env` a la racine du dossier `front`:

```
VITE_API_BASE=http://127.0.0.1:3000
VITE_WS_API_KEY=
```

## Demo communication securisee

Le panneau "Secure Chat" fait une demo WebSocket:

- Connexion a `ws://<backend>/ws/secure`
- Echange de cles RSA (partage de cle publique)
- Chiffrement d'une cle AES avec RSA
- Chiffrement des messages en AES-GCM

Assure-toi que le backend est lance avant d'ouvrir cette section.

## Notes

- Les champs `*_base64` attendent du base64 valide.
- Les champs `*_hex` attendent de l'hex (longueur paire).
- Les entrees sont volontairement simples pour la lisibilite.
