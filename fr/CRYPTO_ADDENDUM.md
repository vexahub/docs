# VexaHub - Spécification cryptographique | **Addenda**

> **Version du document :** 3
>
> **Statut :** (Brouillon) Proposé

**Document parent :** [VexaHub - Spécification cryptographique](/fr/CRYPTO.md)

## 20 Journal d'audit

### 20.1 Objectif

Le **journal d'audit** donne aux utilisateurs un enregistrement des actions **sensibles sur le plan de la sécurité** effectuées sur leur compte. Il remplit **deux** objectifs : permettre aux utilisateurs de **détecter** des actions qu'ils **n'ont pas** effectuées (comme des partages créés par un **client compromis**), et fournir un **enregistrement forensique** pour la réponse aux incidents.

Le **journal d'audit** est **activé par défaut** à la création du compte. Les utilisateurs peuvent le désactiver dans les paramètres du compte. Tant qu'il est désactivé, aucun événement n'est journalisé, et les événements de cette période ne le sont jamais rétroactivement.

Chaque entrée est **scellée** : le serveur la chiffre avec la clé publique X-Wing de l'utilisateur au moment où il l'écrit ([§20.9](#209-entrées-scellées)). Le serveur voit l'événement à l'instant où il se produit, mais ne peut plus relire l'historique ensuite. Les entrées sont purgées après **6 mois**.

Le **journal d'audit** ne fournit **pas de preuve cryptographique d'authenticité**. Un **serveur compromis** peut **forger** ou **supprimer** des entrées du journal. Il s'agit d'un mécanisme de transparence, non d'un mécanisme de sécurité contraignant.

### 20.2 Événements journalisés

Les événements suivants **DOIVENT** être journalisés :

| Événement                                            | Valeur `event`                      | Champs journalisés                                                                        |
| ---------------------------------------------------- | ----------------------------------- | ----------------------------------------------------------------------------------------- |
| Connexion (réussie)                                  | `login_success`                     | `timestamp`, `ip_network`, `user_agent`, `session_id`                                     |
| Connexion (échouée)                                  | `login_failed`                      | `timestamp`, `ip_network`, `user_agent`                                                   |
| Inscription                                          | `registration`                      | `timestamp`, `ip_network`, `user_agent`                                                   |
| Changement de mot de passe                           | `password_change`                   | `timestamp`, `ip_network`, `session_id`                                                   |
| Rotation de la phrase de récupération                | `recovery_phrase_rotation`          | `timestamp`, `session_id`                                                                 |
| Rotation de la paire de clés de partage              | `sharing_keypair_rotation`          | `timestamp`, `session_id`                                                                 |
| Partage créé (sortant)                               | `share_created`                     | `timestamp`, `session_id`, `recipient_id`, `share_id`, `share_kind`, `permission`         |
| Partage accepté (entrant)                            | `share_accepted`                    | `timestamp`, `session_id`, `sender_id`, `share_id`                                        |
| Partage révoqué                                      | `share_revoked`                     | `timestamp`, `session_id`, `share_id`                                                     |
| Session persistante créée                            | `persistent_session_created`        | `timestamp`, `device_label`, `session_id`                                                 |
| Session persistante révoquée                         | `persistent_session_revoked`        | `timestamp`, `device_label`                                                               |
| Fichier déplacé                                      | `file_move`                         | `timestamp`, `session_id`, `file_id`, `source_collection_id`, `destination_collection_id` |
| Fichier mis à la corbeille                           | `file_trashed`                      | `timestamp`, `session_id`, `file_id`, `collection_id`                                     |
| Fichier restauré                                     | `file_restored`                     | `timestamp`, `session_id`, `file_id`, `collection_id`                                     |
| Fichier supprimé définitivement                      | `file_deleted`                      | `timestamp`, `session_id`, `file_id`                                                      |
| Collection mise à la corbeille                       | `collection_trashed`                | `timestamp`, `session_id`, `collection_id`                                                |
| Collection restaurée                                 | `collection_restored`               | `timestamp`, `session_id`, `collection_id`                                                |
| Collection supprimée définitivement                  | `collection_deleted`                | `timestamp`, `session_id`, `collection_id`                                                |
| Réinitialisation destructive                         | `destructive_reset`                 | `timestamp`, `ip_network`                                                                 |
| Suppression de compte initiée                        | `account_deletion_initiated`        | `timestamp`, `ip_network`                                                                 |
| Rétractation (droit de rétractation sur un paiement) | `withdrawal`                        | `timestamp`, `session_id`, `payment_id`                                                   |
| Code de secours 2FA utilisé                          | `two_factor_recovery_code_used`     | `timestamp`, `ip_network`, `user_agent`                                                   |
| Codes de secours 2FA renouvelés                      | `two_factor_recovery_codes_renewed` | `timestamp`, `ip_network`, `user_agent`                                                   |
| Journal d'audit activé                               | `audit_log_enabled`                 | `timestamp`, `session_id`                                                                 |
| Journal d'audit désactivé                            | `audit_log_disabled`                | `timestamp`, `session_id`                                                                 |

Les noms de fichiers et de collections ne sont **JAMAIS** journalisés. Ils sont **chiffrés** dans les blobs `VXFM` et `VXCM` et le serveur **ne les voit jamais**. `share_kind` indique si une collection ou un fichier a été partagé, mais **pas** son nom ni son contenu.

Les événements **journal d'audit activé** et **journal d'audit désactivé** sont écrits quel que soit l'état actuel. L'activation écrit toujours la première entrée, et la désactivation écrit toujours la dernière, afin que l'utilisateur dispose d'un enregistrement clair des périodes pendant lesquelles la journalisation était active.

### 20.3 Stockage

Les entrées du **journal d'audit** sont stockées dans une table `audit_log` dédiée. Seules les colonnes nécessaires à la pagination et à la purge sont en clair ; tout le reste est scellé ([§20.9](#209-entrées-scellées)). L'état est suivi par `users.audit_log_enabled` ([CRYPTO §10.1](/fr/CRYPTO.md#101-table-des-utilisateurs)), à `TRUE` par défaut :

```sql
-- users.audit_log_enabled BOOLEAN NOT NULL DEFAULT TRUE

CREATE TABLE audit_log (
    id          UUID PRIMARY KEY DEFAULT uuidv7(),   -- entry_id
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kem_ct      BYTEA NOT NULL,   -- texte chiffré X-Wing, 1120 octets
    vxal        BYTEA NOT NULL,   -- entrée scellée, voir §20.9
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX audit_log_user_created_idx ON audit_log (user_id, created_at DESC);
```

Le rôle de **base de données applicative** **NE DOIT PAS** disposer de `UPDATE` sur `audit_log` : une entrée écrite n'est jamais modifiée. L'application garde `INSERT`, `SELECT` et `DELETE`, car l'utilisateur peut effacer son journal ([§20.5](#205-effacement-du-journal-daudit)), la suppression de compte le supprime ([CRYPTO §19.3](/fr/CRYPTO.md#193-suppression-de-compte)) et la purge de rétention retire les anciennes entrées.

**Rétention :** **6 mois**. Une tâche planifiée quotidienne supprime les entrées dont `created_at` a plus de 6 mois.

### 20.4 Activation et désactivation

Le journal d'audit est activé à la création du compte (`audit_log_enabled = TRUE`). Les utilisateurs le basculent via :

```sh
POST /api/v1/account/audit-log/enable
POST /api/v1/account/audit-log/disable
```

Les deux points d'accès requièrent une session authentifiée active. À l'activation, le serveur définit `audit_log_enabled = TRUE` et écrit une entrée **journal d'audit activé** comme premier événement. À la désactivation, le serveur écrit une entrée **journal d'audit désactivé** comme dernier événement, puis définit `audit_log_enabled = FALSE`. Cela garantit que le journal contient toujours un enregistrement clair des périodes pendant lesquelles la journalisation était active.

La désactivation du journal d'audit ne **supprime pas** les entrées existantes. L'utilisateur conserve l'accès aux événements précédemment collectés jusqu'à ce qu'ils atteignent la rétention de 6 mois. Si l'utilisateur souhaite effacer son journal, il le fait explicitement (voir [§20.5](#205-effacement-du-journal-daudit)).

### 20.5 Effacement du journal d'audit

Les utilisateurs peuvent supprimer explicitement toutes leurs entrées du journal d'audit :

```sh
DELETE /api/v1/account/audit-log
```

Cela supprime définitivement toutes les entrées de l'utilisateur authentifié. Cela ne **désactive pas** la journalisation d'audit. Si la journalisation est activée, les nouveaux événements continuent d'être enregistrés après l'effacement. L'opération d'effacement elle-même n'est **pas** journalisée, puisque le journal est en train d'être vidé.

### 20.6 Accès côté utilisateur

Les **utilisateurs** peuvent récupérer leur propre journal d'audit via :

```rs
GET /api/v1/account/audit-log?limit=50&before={cursor}

<- {
    "entries": [
      {
        "id": "...",
        "kem_ct": "<base64url>",
        "vxal": "<base64url>",
        "created_at": "2026-04-30T12:00:00Z"
      }
    ],
    "next_cursor": "..."
   }
```

> La réponse utilise une pagination par curseur. Le serveur ne renvoie que des entrées scellées ; le client les ouvre dans le Crypto Worker ([§20.9](#209-entrées-scellées)).
>
> `recipient_id` et `sender_id` dans les événements de partage sont des UUIDs à l'intérieur du `metadata` scellé. Le client les résout en noms d'affichage via le point d'accès de recherche d'utilisateurs existant. Le serveur ne stocke ni ne retourne de noms d'utilisateurs ou d'emails dans le journal d'audit.

Le backend est écrit en TypeScript. Avant de sceller une entrée, il **DOIT** tronquer l'IP client à **/24 (IPv4)** ou **/48 (IPv6)**, bits d'hôte mis à zéro, et stocker le résultat comme chaîne CIDR dans `ip_network`. L'IP complète du client n'entre jamais dans le journal d'audit.

La table `sessions` stocke l'IP exacte du client en tant que `INET`, puisqu'elle sert à des fins de sécurité (affichage des sessions actives, réponse aux incidents) et est automatiquement purgée quand la session expire.

### 20.7 Limitations

- Un **serveur compromis** peut supprimer ou fabriquer des entrées du journal. Le **journal d'audit** est un outil de transparence au mieux-effort, **pas une garantie cryptographique**.
- Le serveur voit chaque événement au moment où il l'écrit et pourrait le copier ailleurs. Le scellement protège l'**historique** et protège contre une **fuite de la base** ; il ne protège pas contre un serveur malveillant en direct.
- L'opérateur ne peut plus consulter le journal, y compris pour le support.
- Les **actions** effectuées par un **client compromis** apparaissent légitimes dans le journal. Le journal enregistre qu'un partage a été créé depuis la session de l'utilisateur, mais **ne peut pas** distinguer **l'utilisateur** du **code malveillant** s'exécutant dans le **même contexte de session**.
- Le journal n'enregistre **pas** les accès au contenu des fichiers (événements de téléchargement). Enregistrer chaque téléchargement produirait un **bruit à fort volume** et **exposerait les schémas d'accès** à quiconque pouvant lire le journal. Les **utilisateurs** ayant besoin de pistes d'audit de téléchargement devraient considérer toute création de partage comme impliquant un accès potentiel par le destinataire.
- Les événements des périodes où le journal était **désactivé** sont **définitivement non enregistrés**.
- Une **rotation des clés de partage** ([CRYPTO §11.3](/fr/CRYPTO.md#113-rotation-de-la-paire-de-clés-de-partage)) rend les entrées antérieures illisibles. Le client **DOIT** les déchiffrer et proposer un export avant de lancer la rotation.
- Une **réinitialisation destructive** purge le journal avec le reste du compte : les anciennes entrées seraient de toute façon indéchiffrables.

### 20.8 Ajout au modèle de menace

| Capacité de l'attaquant                                                             | Réponse de VexaHub                                                                                                                        |
| ----------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| Un client compromis crée des partages à l'insu de l'utilisateur                     | Détectable via les entrées `share_created` dans le journal d'audit, visible à la prochaine connexion (si la journalisation était activée) |
| Le serveur supprime ou forge des entrées du journal d'audit                         | Non préventable au niveau crypto ; limitation reconnue documentée au [§20.7](#207-limitations)                                            |
| Un attaquant lit le journal d'audit d'un autre utilisateur                          | Bloqué : le point d'accès du journal est limité à l'utilisateur authentifié; l'accès inter-utilisateurs retourne 403                      |
| Vol de la base de données                                                           | Journal illisible sans la clé de désencapsulation X-Wing de l'utilisateur ; seuls `id`, `user_id` et `created_at` sont en clair           |
| L'utilisateur ne sait pas que la journalisation était désactivée lors d'un incident | L'événement `audit_log_disabled` marque la limite; les lacunes dans le journal sont visibles par horodatage                               |

### 20.9 Entrées scellées

Chaque entrée est chiffrée par le serveur pour l'utilisateur, avec la clé publique X-Wing de l'utilisateur (`users.sharing_public_xwing`), au moment de l'écriture.

**Écriture :**

```rs
(kem_ct, sharedSecret) = X-Wing.Encaps(sharing_public_xwing)

auditKey = HKDF-SHA-512(
    ikm  = sharedSecret,
    salt = 32 octets zéro,
    info = "vexahub:v1:auditLog:" || entry_uuid,
    L    = 32
)

vxal = XChaCha20-Poly1305(auditKey, nonce, clair, AAD)
```

Le serveur oublie ensuite `sharedSecret` et `auditKey`. Il ne garde aucun moyen de déchiffrer l'entrée.

**Blob `VXAL` :**

```rs
Décalage  Taille  Champ
--------  ------  ---------------------------------------
0         4       Magique "VXAL" (0x56 0x58 0x41 0x4C)
4         1       Version de format (0x01)
5         1       Identifiant d'algorithme KEM (0x02 = X-Wing)
6         24      Nonce (aléatoire)
30        N+16    Texte chiffré (CBOR canonique) + tag
```

```rs
AAD : user_id ‖ entry_id (32 octets, UUIDs bruts)
```

Le texte chiffré X-Wing (`kem_ct`, 1120 octets) est stocké à côté du blob, dans sa propre colonne.

**Colonnes en clair :** `id`, `user_id`, `created_at` seulement, pour la pagination et la purge.

**Champs scellés**, en CBOR canonique ([RFC 8949 §4.2.1][cbor_rfc]) :

```json
{
  "event":      tstr,          // valeur event du §20.2
  "metadata":   map,           // champs de l'événement du §20.2
  "ip_network": tstr / null,   // CIDR, /24 ou /48
  "user_agent": tstr / null,
}
```

Ordre canonique : `event` < `metadata` < `ip_network` < `user_agent` (longueur d'abord, puis octet par octet).

**Lecture :** le client récupère les entrées ([§20.6](#206-accès-côté-utilisateur)) et les ouvre dans le Crypto Worker : `X-Wing.Decaps` avec la clé de désencapsulation issue de `VXSK`, la même dérivation HKDF, puis le déchiffrement AEAD avec l'AAD ci-dessus. Un déchiffrement en échec est affiché comme une entrée illisible, jamais ignoré en silence.

**Séparation de domaine HKDF :** la chaîne d'info `"vexahub:v1:auditLog:"` est distincte de toutes les chaînes d'info du [CRYPTO §4](/fr/CRYPTO.md#4-séparation-de-domaine-hkdf).

## 21 Création de sous-collection par un éditeur

> Implémenté côté serveur (`POST /api/v1/shares/{shareId}/subcollections`). Pas encore utilisé par la webapp : la dérivation de clé est définie dans `engine.ts` (`deriveChildCollectionKeyWrapKey`) mais n'est pas appelée.

Lorsqu'un destinataire disposant de la permission `edit` crée une **sous-collection** dans une collection partagée, la sous-collection appartient au propriétaire de la collection parente **immédiatement à la création**. Aucune fenêtre d'attente, aucun TTL, aucun transfert requis.

### 21.1 Dérivation des clés

La `childCollectionKeyWrapKey` est dérivée depuis la `collectionKey` parente, en miroir de la dérivation `fileKeyWrap` au [§4](/fr/CRYPTO.md#4-séparation-de-domaine-hkdf) :

| Dérivation                                         | Chaîne `info`                                    | Longueur |
| -------------------------------------------------- | ------------------------------------------------ | -------- |
| `childCollectionKeyWrapKey` depuis `collectionKey` | `vexahub:v1:childCollectionKeyWrap:{child_uuid}` | 32       |

```rust
childCollectionKeyWrapKey = HKDF-SHA-512(
    ikm  = parentCollectionKey,     // collectionKey de la collection parente
    salt = 32 octets zéro,
    info = "vexahub:v1:childCollectionKeyWrap:" || child_uuid,
    L    = 32
)
```

L'IKM est une sortie **CSPRNG** uniformément aléatoire (héritée de `collectionKey`), donc un sel zéro n'a aucun impact sur la sécurité conformément à la politique de sel au [§4](/fr/CRYPTO.md#4-séparation-de-domaine-hkdf). Tous les UUIDs dans les chaînes `info` sont encodés en binaire big-endian brut de 16 octets.

### 21.2 Flux de création

1. L'éditeur génère une nouvelle `collectionKey` via **CSPRNG**.
2. L'éditeur génère un `child_uuid` côté client (UUID v7).
3. L'éditeur dérive `childCollectionKeyWrapKey` depuis `parentCollectionKey` et `child_uuid`.
4. L'éditeur encapsule `collectionKey` avec `childCollectionKeyWrapKey` -> blob `VXCC`.

   `VXCC` a la même structure que `VXCK` (78 octets), avec le magique `"VXCC"` (0x56 0x58 0x43 0x43) et l'AAD `parent_id ‖ collection_id` (32 octets, UUIDs bruts). Le magique indique à tout lecteur de le désencapsuler avec la `collectionKey` parente, et non avec une `masterKey`.

5. Éditeur -> Serveur : `POST /api/v1/shares/{shareId}/subcollections` avec :
   - `id` (`child_uuid` généré côté client)
   - `parentId` : la collection partagée, ou une collection accordée à ce partage
   - `vxcm` (métadonnées de collection chiffrées)
   - `vxcc` (`collectionKey` encapsulée)
6. Le serveur **DOIT** vérifier :
   - Le partage est accepté, non révoqué, et a le bit `edit` (`0x02`). Rejet `HTTP 403` sinon.
   - Le parent est accessible via le partage et appartient au propriétaire du partage. Rejet `HTTP 404` sinon.
   - L'`id` fourni n'existe pas déjà. Rejet `HTTP 409` en cas de doublon.
7. Le serveur crée la ligne de collection avec `user_id = parent_collection_owner_id` immédiatement, stocke `VXCC` dans `collection_keys` pour le propriétaire, et copie le même `VXCC` dans `share_collection_keys` pour **chaque partage non révoqué** qui atteint la parente (la parente est la collection partagée ou lui est accordée). Un `VXCC` n'est lié à aucun utilisateur : les mêmes octets servent à tous les destinataires, et l'accès reste contrôlé côté serveur.
8. Le serveur répond `201` avec la collection.

### 21.3 Accès

L'éditeur et le propriétaire dérivent tous deux `childCollectionKeyWrapKey` depuis leur copie de `parentCollectionKey` et le `child_uuid`. Les deux peuvent désencapsuler `collectionKey` depuis le blob `VXCC` indépendamment.

- **Propriétaire** : dispose de `parentCollectionKey` via son propre `VXCK` -> dérive `childCollectionKeyWrapKey` -> désencapsule la `collectionKey` de la sous-collection. L'accès est immédiat, aucune interaction requise.
- **Éditeur** : dispose de `parentCollectionKey` via son partage -> dérive `childCollectionKeyWrapKey` -> désencapsule la `collectionKey` de la sous-collection. L'accès persiste tant que son partage `edit` sur la collection parente reste valide.

**Réencapsulation par le propriétaire (`VXCC` transitoire) :**

> Prévu, non implémenté dans la version 1 du protocole

La première fois que le client du propriétaire désencapsule un `VXCC` de ses propres `collection_keys`, il **DOIT** :

1. Réencapsuler la même `collectionKey` avec `collectionKeyWrapKey` dérivée de `masterKey` -> `VXCK` classique (AAD `user_id ‖ collection_id`).
2. Envoyer `PUT /api/v1/storage/collections/{id}/key { vxck, keyGeneration }`, où `keyGeneration` est celle du `VXCC` désencapsulé.

Le serveur **DOIT** l'accepter uniquement du propriétaire de la collection, uniquement si le blob stocké est encore un `VXCC` à cette `keyGeneration`, et **DOIT** le remplacer sur place. Sinon il répond `HTTP 409` (blob changé, par exemple après une rotation) ou `HTTP 403` (compte en lecture seule) : le client continue avec le `VXCC` et réessaie lors d'un prochain déchiffrement.

Les copies `VXCC` dans `share_collection_keys` ne sont pas touchées.

> La vérification de la permission `edit` (bit `0x02`) est appliquée uniquement côté serveur. Un éditeur avec la permission `view` (`0x01`) détient techniquement `parentCollectionKey` et pourrait dériver `childCollectionKeyWrapKey` côté client, mais le serveur rejette toute tentative de création avec `HTTP 403`. Cela est cohérent avec [§11.6](/fr/CRYPTO.md#116-permissions-de-partage) : les permissions sont appliquées au niveau de la couche serveur, pas au niveau cryptographique.

### 21.4 Révocation de partage, rotation de clé et déplacement

**Rotation.** Lorsqu'un partage sur la collection parente est révoqué, la rotation des clés se déroule conformément au [§11.1](/fr/CRYPTO.md#111-révocation-de-partage) :

1. La `parentCollectionKey` est renouvelée.
2. Chaque `VXCC` sous la parente (copie du propriétaire pas encore remplacée, et copies des partages) est désencapsulé avec l'**ancienne** `childCollectionKeyWrapKey` et réencapsulé avec celle dérivée de la **nouvelle** `parentCollectionKey`, dans le même appel de rotation (CRYPTO §11.1 étape 7a). Le propriétaire peut à la place remplacer sa propre copie par un `VXCK` classique.
3. Les lignes `share_collection_keys` de l'éditeur révoqué sont supprimées avec le partage. Il n'a pas accès à la nouvelle `parentCollectionKey`.

**Déplacement.** Un `VXCC` est lié à sa parente à la fois par la clé d'encapsulation et par l'AAD :

1. Le serveur **DOIT** refuser de déplacer une collection dont la copie du propriétaire est encore un `VXCC` (`HTTP 409`). Le client du propriétaire la remplace d'abord par un `VXCK` (§21.3).
2. Lors d'un déplacement, le serveur supprime les copies `VXCC` de cette collection dans `share_collection_keys`. Le propriétaire redonne l'accès par le flux d'accord classique, avec des clés encapsulées par partage.

### 21.5 Schéma

Aucune nouvelle table ni colonne. Les sous-collections créées par les éditeurs utilisent les tables `collections`, `collection_keys` et `share_collection_keys` existantes. Le type de blob est porté par son magique (`VXCC` ou `VXCK`). Le serveur accepte un `id` fourni par le client (UUID v7) lors de la création de collection et applique l'unicité.

```sql
-- Aucun changement de schéma au-delà de ce que §11.1 requiert déjà.
-- collections.user_id = parent_collection_owner_id à la création.
```

### 21.6 Séparation de domaine HKDF

La chaîne d'info `"vexahub:v1:childCollectionKeyWrap:"` est distincte de toutes les chaînes d'info existantes au [§4](/fr/CRYPTO.md#4-séparation-de-domaine-hkdf). Aucun incrément de version de protocole requis.

### 21.7 Garanties

| Propriété                                                                     | Statut                                                              |
| ----------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| L'éditeur dispose d'un accès immédiat après la création                       | ✅                                                                  |
| Le propriétaire dispose d'un accès cryptographique immédiat après la création | ✅ Aucune fenêtre d'attente                                         |
| Le propriétaire est le vrai propriétaire dès la création                      | ✅ `user_id = owner_id` à l'insertion                               |
| Aucun TTL, aucun état en attente, aucun transfert                             | ✅                                                                  |
| Le serveur peut lire le contenu de la sous-collection                         | ❌ Zéro connaissance préservée                                      |
| L'éditeur perd l'accès lors de la révocation du partage parent                | ✅ La rotation de `parentCollectionKey` invalide l'accès            |
| Le propriétaire conserve l'accès après la rotation de `parentCollectionKey`   | ✅ Réencapsulée en `VXCK` classique, indépendante de la clé parente |
| `VXCC` est transitoire côté propriétaire                                      | ✅ Remplacé par un `VXCK` au premier déchiffrement (§21.3)          |
| Le serveur rejette la création si l'éditeur manque la permission `edit`       | ✅ HTTP 403 sur bit `0x02` manquant                                 |
| Aucun incrément de version de protocole requis                                | ✅ Nouvelle chaîne d'info HKDF uniquement                           |

## Historique des modifications

- **3 :** journal d'audit activé par défaut, scellé avec la clé publique X-Wing de l'utilisateur, rétention de 6 mois (§20.1, §20.3, §20.4, nouveau §20.9). Liste des événements alignée sur le code (§20.2). Seul `UPDATE` est retiré au rôle applicatif (§20.3). Masquage d'IP décrit pour le backend TypeScript (§20.6). §21 renommé en `childCollectionKeyWrap`, UUID v7, route réelle, marqué comme prévu. Blob `VXCC` pour la clé de sous-collection, réencapsulé en `VXCK` par le propriétaire (§21.2 à §21.5, §21.7).

[//]: # "LINKS"
[cbor_rfc]: https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1
