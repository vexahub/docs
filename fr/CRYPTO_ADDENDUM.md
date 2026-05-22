# VexaHub - Spécification cryptographique | **Addenda**

> **Version du document :** 2
>
> **Statut :** (Brouillon) Proposé

**Document parent :** [VexaHub - Spécification cryptographique](/fr/CRYPTO.md)

## 20 Journal d'audit

### 20.1 Objectif

Le **journal d'audit** donne aux utilisateurs un enregistrement des actions **sensibles sur le plan de la sécurité** effectuées sur leur compte. Il remplit **deux** objectifs : permettre aux utilisateurs de **détecter** des actions qu'ils **n'ont pas** effectuées (comme des partages créés par un **client compromis**), et fournir un **enregistrement forensique** pour la réponse aux incidents.

Le **journal d'audit** est **opt-in**. Les utilisateurs l'activent explicitement dans les paramètres du compte. Aucun événement n'est journalisé jusqu'à ce que l'utilisateur l'active. Le journal ne couvre que les événements à partir du moment où il a été activé. L'activité antérieure du compte n'est jamais journalisée rétroactivement.

Le **journal d'audit** ne fournit **pas de preuve cryptographique d'authenticité**. Un **serveur compromis** peut **forger** ou **supprimer** des entrées du journal. Il s'agit d'un mécanisme de transparence, non d'un mécanisme de sécurité contraignant.

### 20.2 Événements journalisés

Les événements suivants **DOIVENT** être journalisés :

| Événement                              | Champs journalisés                                                                                       |
|----------------------------------------|----------------------------------------------------------------------------------------------------------|
| Connexion (réussie)                    | `timestamp`, `ip_network`, `user_agent`, `session_id`                                                    |
| Connexion (échouée)                    | `timestamp`, `ip_network`, `user_agent`                                                                  |
| Inscription                            | `timestamp`, `ip_network`, `user_agent`                                                                  |
| Changement de mot de passe             | `timestamp`, `ip_network`, `session_id`                                                                  |
| Rotation de la phrase de récupération  | `timestamp`, `session_id`                                                                                |
| Rotation de la paire de clés de partage| `timestamp`, `session_id`                                                                                |
| Partage créé (sortant)                 | `timestamp`, `session_id`, `recipient_id`, `share_id`, `share_kind`, `permission`                        |
| Partage accepté (entrant)              | `timestamp`, `session_id`, `sender_id`, `share_id`                                                       |
| Partage révoqué                        | `timestamp`, `session_id`, `share_id`                                                                    |
| Session persistante créée              | `timestamp`, `device_label`, `session_id`                                                                |
| Session persistante révoquée           | `timestamp`, `device_label`                                                                              |
| Fichier déplacé                        | `timestamp`, `session_id`, `file_id`, `source_collection_id`, `destination_collection_id`                |
| Fichier mis à la corbeille             | `timestamp`, `session_id`, `file_id`, `collection_id`                                                    |
| Fichier restauré                       | `timestamp`, `session_id`, `file_id`, `collection_id`                                                    |
| Fichier supprimé définitivement        | `timestamp`, `session_id`, `file_id`                                                                     |
| Collection mise à la corbeille         | `timestamp`, `session_id`, `collection_id`                                                               |
| Collection restaurée                   | `timestamp`, `session_id`, `collection_id`                                                               |
| Collection supprimée définitivement    | `timestamp`, `session_id`, `collection_id`                                                               |
| Réinitialisation destructive           | `timestamp`, `ip_network`                                                                                |
| Suppression de compte initiée          | `timestamp`, `ip_network`                                                                                |

Les noms de fichiers et de collections ne sont **JAMAIS** journalisés. Ils sont **chiffrés** dans les blobs `VXFM` et `VXCM` et le serveur **ne les voit jamais**. `share_kind` indique si une collection ou un fichier a été partagé, mais **pas** son nom ni son contenu.

Les événements **journal d'audit activé** et **journal d'audit désactivé** sont écrits indépendamment de l'état opt-in actuel. L'activation écrit toujours la première entrée, et la désactivation écrit toujours la dernière, afin que l'utilisateur dispose d'un enregistrement clair des périodes pendant lesquelles la journalisation était active.

### 20.3 Stockage

Les entrées du **journal d'audit** sont stockées dans une table `audit_log` dédiée avec un accès en ajout seul appliqué au niveau des privilèges de la base de données. La table `users` acquiert une colonne `audit_log_enabled` pour suivre l'état opt-in :

```sql
ALTER TABLE users ADD COLUMN audit_log_enabled BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE audit_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event       TEXT NOT NULL,
    metadata    JSONB NOT NULL DEFAULT '{}',
    ip_network  CIDR,         -- /24 IPv4 ou /48 IPv6, bits d'hôte mis à zéro à l'insertion
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ON audit_log (user_id, created_at DESC);
```

Le rôle de **base de données applicative** **DOIT** disposer uniquement des privilèges `INSERT` et `SELECT` sur `audit_log`. Les privilèges `UPDATE` et `DELETE` **NE DOIVENT PAS** être accordés au rôle **applicatif**. Un rôle privilégié **séparé** (non utilisé par l'application) gère les purges de rétention. Cela signifie que l'application **ne peut pas** modifier ni supprimer les entrées du journal **même en cas de compromission**, sauf si l'attaquant monte en privilège au-delà du rôle de base de données applicatif.

La durée de rétention est **configurable par l'opérateur**. Les entrées sont purgées par un job planifié s'exécutant sous le rôle privilégié, **et non le rôle applicatif**.

### 20.4 Activation et désactivation

Les utilisateurs basculent la journalisation d'audit via :

```sh
POST /api/v1/account/audit-log/enable
POST /api/v1/account/audit-log/disable
```

Les deux points d'accès requièrent une session authentifiée active. À l'activation, le serveur définit `audit_log_enabled = TRUE` et écrit une entrée **journal d'audit activé** comme premier événement. À la désactivation, le serveur écrit une entrée **journal d'audit désactivé** comme dernier événement, puis définit `audit_log_enabled = FALSE`. Cela garantit que le journal contient toujours un enregistrement clair des périodes pendant lesquelles la journalisation était active.

La désactivation du journal d'audit ne **supprime pas** les entrées existantes. L'utilisateur conserve l'accès aux événements précédemment collectés. Si l'utilisateur souhaite effacer son journal, il le fait explicitement (voir [§20.5](#205-effacement-du-journal-daudit)).

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
        "event": "share_created",
        "metadata": { "recipient_id": "...", "share_kind": "collection" },
        "ip_network": "192.168.1.0/24",
        "created_at": "2026-04-30T12:00:00Z"
      }
    ],
    "next_cursor": "..."
   }
```

> La réponse utilise une pagination par curseur. `ip_network` est tronqué à un préfixe /24 (IPv4) ou /48 (IPv6) avant le stockage et l'affichage, de sorte que les adresses IP précises des clients ne sont jamais conservées ni retournées.
>
> `recipient_id` et `sender_id` dans les événements de partage sont retournés sous forme d'UUIDs. Le client les résout en noms d'affichage via le point d'accès de recherche d'utilisateurs existant. Le serveur ne stocke ni ne retourne de noms d'utilisateurs ou d'emails dans le journal d'audit.

L'application **DOIT** tronquer l'IP client à **/24 (IPv4)** ou **/48 (IPv6)** avant l'insertion, avec les bits d'hôte **explicitement** mis à zéro. Le type de colonne `CIDR` rejette les valeurs où les bits d'hôte sont définis, fournissant une protection au niveau base de données contre le stockage accidentel d'IP complètes :

```rust
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

fn coarsen(client_ip: IpAddr) -> IpNet {
    match client_ip {
        IpAddr::V4(v4) => IpNet::V4(Ipv4Net::new(v4, 24).unwrap().trunc()),
        IpAddr::V6(v6) => IpNet::V6(Ipv6Net::new(v6, 48).unwrap().trunc()),
    }
}
```

L'appel `.trunc()` met les bits d'hôte à zéro, ce qu'exige le type `CIDR` de PostgreSQL.

La table des `sessions` stockent l'IP exacte du client en tant que `INET`, puisque c'est utilisé pour des raisons de sécurité (affichage des sessions active, réponse aux incidents) et est automatiquement purgé quand la session expire.

### 20.7 Limitations

- Un **serveur compromis** peut supprimer ou fabriquer des entrées du journal. Le **journal d'audit** est un outil de transparence au mieux-effort, **pas une garantie cryptographique**.
- Les **actions** effectuées par un **client compromis** apparaissent légitimes dans le journal. Le journal enregistre qu'un partage a été créé depuis la session de l'utilisateur, mais **ne peut pas** distinguer **l'utilisateur** du **code malveillant** s'exécutant dans le **même contexte de session**.
- Le journal n'enregistre **pas** les accès au contenu des fichiers (événements de téléchargement). Enregistrer chaque téléchargement produirait un **bruit à fort volume** et **exposerait les schémas d'accès** à quiconque pouvant lire le journal. Les **utilisateurs** ayant besoin de pistes d'audit de téléchargement devraient considérer toute création de partage comme impliquant un accès potentiel par le destinataire.
- Le journal ne couvre que les événements à partir du moment où il a été activé. L'activité antérieure du compte n'est **jamais** journalisée rétroactivement. Si l'utilisateur **désactive** et **réactive** la journalisation, les événements pendant la période désactivée sont **définitivement non enregistrés**.

### 20.8 Ajout au modèle de menace

| Capacité de l'attaquant                                                             | Réponse de VexaHub                                                                                                                              |
|-------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| Un client compromis crée des partages à l'insu de l'utilisateur                     | Détectable via les entrées `share_created` dans le journal d'audit, visible à la prochaine connexion (si la journalisation était activée)       |
| Le serveur supprime ou forge des entrées du journal d'audit                         | Non préventable au niveau crypto ; limitation reconnue documentée au [§20.7](#207-limitations)                                                  |
| Un attaquant lit le journal d'audit d'un autre utilisateur                          | Bloqué : le point d'accès du journal est limité à l'utilisateur authentifié; l'accès inter-utilisateurs retourne 403                            |
| L'utilisateur ne sait pas que la journalisation était désactivée lors d'un incident | L'événement `audit_log_disabled` marque la limite; les lacunes dans le journal sont visibles par horodatage                                     |

## 21 Création de sous-collection par un éditeur (susceptible d'être modifiée)

Lorsqu'un destinataire disposant de la permission `edit` crée une **sous-collection** dans une collection partagée, la sous-collection appartient au propriétaire de la collection parente **immédiatement à la création**. Aucune fenêtre d'attente, aucun TTL, aucun transfert requis.

### 21.1 Dérivation des clés

La `subCollectionWrapKey` est dérivée depuis la `collectionKey` parente, en miroir de la dérivation `fileKeyWrap` au [§4](/fr/CRYPTO.md#4-séparation-de-domaine-hkdf) :

| Dérivation                                        | Chaîne `info`                                          | Longueur |
|---------------------------------------------------|--------------------------------------------------------|----------|
| `subCollectionWrapKey` depuis `collectionKey`     | `vexahub:v1:subCollectionWrap:{subcollection_uuid}`    | 32       |

```rust
subCollectionWrapKey = HKDF-SHA-512(
    ikm  = parentCollectionKey,     // collectionKey de la collection parente
    salt = 32 octets zéro,
    info = "vexahub:v1:subCollectionWrap:" || subcollection_uuid,
    L    = 32
)
```

L'IKM est une sortie **CSPRNG** uniformément aléatoire (héritée de `collectionKey`), donc un sel zéro n'a aucun impact sur la sécurité conformément à la politique de sel au [§4](/fr/CRYPTO.md#4-séparation-de-domaine-hkdf). Tous les UUIDs dans les chaînes `info` sont encodés en binaire big-endian brut de 16 octets.

### 21.2 Flux de création

1. L'éditeur génère une nouvelle `collectionKey` via **CSPRNG**.
2. L'éditeur génère un `subcollection_uuid` côté client (UUID v4).
3. L'éditeur dérive `subCollectionWrapKey` depuis `parentCollectionKey` et `subcollection_uuid`.
4. L'éditeur encapsule `collectionKey` avec `subCollectionWrapKey` -> blob `VXCK`.
5. Éditeur -> Serveur : `POST /api/v1/collections` avec :
   - `id` (`subcollection_uuid` généré côté client)
   - `parent_id` de la collection partagée
   - `vxcm` (métadonnées de collection chiffrées)
   - `vxck` (`collectionKey` encapsulée)
6. Le serveur **DOIT** vérifier :
   - Le partage de l'éditeur sur la collection parente a le bit `edit` (`0x02`) défini. Rejet `HTTP 403` sinon.
   - L'`id` fourni est un UUID valide et n'existe pas déjà. Rejet `HTTP 409` en cas de doublon.
7. Le serveur crée la ligne de collection avec `user_id = parent_collection_owner_id` immédiatement. Le propriétaire est le propriétaire dès le premier instant.
8. Le serveur répond `201` avec le `collection_id`.

### 21.3 Accès

L'éditeur et le propriétaire dérivent tous deux `subCollectionWrapKey` depuis leur copie de `parentCollectionKey` et le `subcollection_uuid`. Les deux peuvent désencapsuler `collectionKey` depuis le blob `VXCK` indépendamment.

- **Propriétaire** : dispose de `parentCollectionKey` via son propre `VXCK` -> dérive `subCollectionWrapKey` -> désencapsule la `collectionKey` de la sous-collection. L'accès est immédiat, aucune interaction requise.
- **Éditeur** : dispose de `parentCollectionKey` via son partage `VXSH` -> dérive `subCollectionWrapKey` -> désencapsule la `collectionKey` de la sous-collection. L'accès persiste tant que son partage `edit` sur la collection parente reste valide.

> La vérification de la permission `edit` (bit `0x02`) est appliquée uniquement côté serveur. Un éditeur avec la permission `view` (`0x01`) détient techniquement `parentCollectionKey` et pourrait dériver `subCollectionWrapKey` côté client, mais le serveur rejette toute tentative de création avec `HTTP 403`. Cela est cohérent avec [§11.6](/fr/CRYPTO.md#116-permissions-de-partage) : les permissions sont appliquées au niveau de la couche serveur, pas au niveau cryptographique.

### 21.4 Révocation de partage et rotation de clé

Lorsque le partage de l'éditeur sur la collection parente est révoqué, la rotation des clés se déroule conformément au [§11.1](/fr/CRYPTO.md#111-révocation-de-partage) :

1. La `parentCollectionKey` est renouvelée. Une nouvelle `collectionKey` est générée pour la collection parente.
2. Le propriétaire désencapsule chaque `collectionKey` de sous-collection en utilisant l'**ancienne** `subCollectionWrapKey` (dérivée de l'ancienne `parentCollectionKey`).
3. Le propriétaire dérive les nouvelles valeurs de `subCollectionWrapKey` depuis la **nouvelle** `parentCollectionKey` et chaque `subcollection_uuid`.
4. Le propriétaire réencapsule chaque `collectionKey` de sous-collection avec la nouvelle `subCollectionWrapKey` -> nouveaux blobs `VXCK`, téléversés vers le serveur.
5. L'éditeur ne peut plus dériver `subCollectionWrapKey`; il n'a pas accès à la nouvelle `parentCollectionKey`.

Le coût est identique à la réencapsulation des blobs `VXFK` après révocation ([§11.1](/fr/CRYPTO.md#111-révocation-de-partage)). Les sous-collections sont traitées comme des ressources encapsulées supplémentaires aux côtés des fichiers.

### 21.5 Schéma

Aucune nouvelle table requise. Les sous-collections créées par les éditeurs utilisent les tables `collections` et `collection_keys` existantes. Le serveur accepte un `id` fourni par le client (UUID v4) lors de la création de collection et applique l'unicité.

```sql
-- Aucun changement de schéma au-delà de ce que §11.1 requiert déjà.
-- collections.user_id = parent_collection_owner_id à la création.
```

### 21.6 Séparation de domaine HKDF

La chaîne d'info `"vexahub:v1:subCollectionWrap:"` est distincte de toutes les chaînes d'info existantes au [§4](/fr/CRYPTO.md#4-séparation-de-domaine-hkdf). Aucun incrément de version de protocole requis.

### 21.7 Garanties

| Propriété                                                                     | Statut                                                              |
|-------------------------------------------------------------------------------|---------------------------------------------------------------------|
| L'éditeur dispose d'un accès immédiat après la création                       | ✅                                                                  |
| Le propriétaire dispose d'un accès cryptographique immédiat après la création | ✅ Aucune fenêtre d'attente                                         |
| Le propriétaire est le vrai propriétaire dès la création                      | ✅ `user_id = owner_id` à l'insertion                               |
| Aucun TTL, aucun état en attente, aucun transfert                             | ✅                                                                  |
| Le serveur peut lire le contenu de la sous-collection                         | ❌ Zéro connaissance préservée                                      |
| L'éditeur perd l'accès lors de la révocation du partage parent                | ✅ La rotation de `parentCollectionKey` invalide l'accès            |
| Le propriétaire conserve l'accès après la rotation de `parentCollectionKey`   | ✅ Réencapsule `VXCK` avec la nouvelle `subCollectionWrapKey`       |
| Le serveur rejette la création si l'éditeur manque la permission `edit`       | ✅ HTTP 403 sur bit `0x02` manquant                                 |
| Aucun incrément de version de protocole requis                                | ✅ Nouvelle chaîne d'info HKDF uniquement                           |
