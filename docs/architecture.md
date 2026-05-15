# Architecture

## Vision

Sikrypt est une API educative qui expose des algorithmes modernes et pedagogiques dans une meme base Rust (Axum).

## Composants

- backend/: API Rust (Axum), logique crypto, routes et tests.
- front/: reserve pour une interface web (a completer).

## Organisation des endpoints

- Moderne: /crypto/\*
- Educatif: /asymmetric/_, /classic/_, /hash/_, /signature/_, /symmetric/_, /comms/_

## Flux principaux

- Requetes HTTP -> routes Axum -> algorithmes -> reponse JSON.
- Erreurs centralisees via ApiError pour garder des reponses propres.

## Observabilite et robustesse

- Traces HTTP (tower-http trace).
- x-request-id propage sur chaque requete.
- Timeout global et limite de concurrence via middleware.
- Rate limit applique sur /crypto/\*.

## Tests et qualite

- Tests unitaires dans les modules algorithmes.
- Tests d'integration pour les routes critiques.
- CI: fmt, clippy, tests.

## Limites educatives

Les endpoints pedagogiques sont destines a l'apprentissage et ne visent pas un usage production.
