# Politique de sécurité

## Signalement de vulnérabilités

**Merci de ne pas ouvrir de tickets pour tout signalement de vulnérabilités.**

Mél: [security@vexahub.com](mailto:security@vexahub.com)

Clé GPG: [51A1030ABEA211C4F22FD7755567F1034E8A2D5C](https://keys.openpgp.org/vks/v1/by-fingerprint/51A1030ABEA211C4F22FD7755567F1034E8A2D5C)

Temps de réponse attendu: **72 heures**. Nous accuserons réception, confirmerons la portée du problème et vous tiendrons informé tout au long du processus. Nous demandons **90 jours** pour remédier au problème avant toute divulgation publique.

## Portée

**Dans la portée:**

- `app.vexahub.com`
- L'API, servie sous `app.vexahub.com/api`
- `checkout.vexahub.com`
- Les pages de liens publics (`app.vexahub.com/share/...`)
- Implémentation des protocoles cryptographiques
- Authentification et gestion des sessions
- Gestion des clés et flux de partage

**Hors de portée:**

- Attaques par déni de service
- Ingénierie sociale
- Attaques par accès physique
- Attaques nécessitant un serveur entièrement compromis agissant de connivence avec lui-même durant une session active (**objectif non visé, documenté**)
- Attaques nécessitant une mise à jour malveillante du client distribuée via le canal de distribution (les **builds reproductibles** sont prévus dans les travaux futurs).

## Architecture cryptographique

VexaHub est un **service de stockage cloud E2EE à connaissance zéro**. Le serveur n'a jamais accès aux mots de passe des utilisateurs, aux fichiers en clair, aux noms de fichiers, ni aux clés de chiffrement lors d'une utilisation normale.

| Couche                 | Algorithme                                                         |
| ---------------------- | ------------------------------------------------------------------ |
| Authentification       | `OPAQUE (RFC 9807)` : Ristretto255, TripleDhKem (3DH + ML-KEM-768) |
| Étirement de clé       | `Argon2id` : 128 Mio / t=3 / p=4                                   |
| Chiffrement symétrique | `XChaCha20-Poly1305` : nonces de 24 octets                         |
| Dérivation de clé      | `HKDF-SHA-512` : séparation par domaine                            |
| KEM de partage         | `X-Wing` (ML-KEM-768 + X25519)                                     |
| Signatures             | `ML-DSA-65` (FIPS 204, niveau 3 NIST)                              |

La spécification complète est publiée sur [docs.vexahub.io](https://docs.vexahub.io).

**Résistance post-quantique :** le KEM hybride `X-Wing` est sûr si **X25519 ou ML-KEM-768** l'est. Les signatures `ML-DSA-65` protègent l'authenticité des partages au niveau de sécurité correspondant. Les transcriptions de connexion sont résistantes aux attaques quantiques via `TripleDhKem` dans l'échange de clés OPAQUE.

## Ce que le serveur ne peut pas faire

Même avec un accès complet à la base de données, le serveur ne peut pas :

- `déchiffrer` les fichiers, noms de fichiers ou métadonnées des utilisateurs
- `mener` des attaques hors-ligne sur les mots de passe (défense OPRF d'`OPAQUE`)
- `connaître` le contenu partagé entre utilisateurs
- `identifier` les utilisateurs possédant des fichiers identiques (identifiants de contenu `BLAKE3` par utilisateur avec clé dédiée)
- `forger` des invitations de partage (signatures `ML-DSA-65` vérifiées côté client)

## Limitations connues

Il s'agit de compromis documentés et acceptés : ce ne sont pas des vulnérabilités.

**Session active avec serveur compromis :** un serveur contrôlant entièrement une session active peut servir des réponses malveillantes. Il s'agit d'une limitation fondamentale de l'E2EE dans les applications web.

**Mise à jour client malveillante :** un canal de distribution compromis peut délivrer un client avec porte dérobée. Les builds reproductibles sont prévus dans les travaux futurs.

**Accès physique à l'appareil :** un attaquant ayant accès physique à un appareil déverrouillé peut accéder aux clés en mémoire.

**Mode « Se souvenir de moi » :** la copie chiffrée de la clé maître (`VXPS`) est stockée sur les serveurs VexaHub, et la clé qui la déchiffre (`localKey`) reste sur l'appareil. Compromis documenté, désactivé par défaut.

**Contenu de fichier après révocation :** la révocation d'un partage bloque immédiatement l'accès à l'API et effectue une rotation des clés, mais ne re-chiffre pas le contenu existant par défaut. Un paramètre de re-chiffrement optionnel est prévu. Les copies téléchargées ne peuvent pas être invalidées rétroactivement : limitation inhérente à l'E2EE.

## Versions supportées

Seule la **version de production actuelle** reçoit des correctifs de sécurité.

## Bug Bounty

Il n'existe **pas de programme de bug bounty formel** pour le moment. Les chercheurs seront crédités dans les notes de version si souhaité.
