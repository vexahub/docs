# VexaHub - Spécification cryptographique | **Addendum**

> **Version du document :** 1
>
> **Statut :** (Brouillon) Proposé

**Document parent :** [VexaHub - Spécification cryptographique](CRYPTO.md)

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

La désactivation du journal d'audit ne **supprime pas** les entrées existantes. L'utilisateur conserve l'accès aux événements précédemment collectés. Si l'utilisateur souhaite effacer son journal, il le fait explicitement (voir §20.5).

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

La colonne `ip_network` de la table `sessions` ([§9.3](/fr/CRYPTO.md#93-session-schemas)) suit la même règle. Mettez également à jour son schéma vers `CIDR` :

```sql
ALTER TABLE sessions ALTER COLUMN ip_network TYPE CIDR USING ip_network::CIDR;
```

Pour les nouveaux déploiements, déclarez-la directement en `CIDR` dès le départ.

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

## 21 Création de sous-collection par un éditeur

Lorsqu'un destinataire disposant de la permission `edit` crée une **sous-collection** dans une collection partagée, la **propriété est transférée au propriétaire de la collection parente** *de manière asynchrone* **via un transfert de clé assisté par le serveur**.

> **Mécanisme de synchronisation :** Toutes les notifications de cette section sont délivrées via le mécanisme de synchronisation défini dans la spécification API. « Notifie via sync » ci-dessous fait toujours référence à ce mécanisme.

### 21.1 Flux de création

1. L'éditeur génère une nouvelle `collectionKey` via **CSPRNG**.
2. L'éditeur encapsule `collectionKey` sous sa propre `masterKey` -> blob `VXCK` (étendue éditeur). **L'éditeur dispose d'un accès immédiat**.
3. L'éditeur encapsule `collectionKey` sous une nouvelle **invitation de partage X-Wing** adressée au propriétaire de la collection parente -> blob `VXSH`. L'invitation **DOIT** définir `"p"` à `0x07` (*voir* + *modifier* + *repartager*). Le propriétaire reçoit des permissions complètes sur la **sous-collection indépendamment du niveau de permission propre de l'éditeur** sur la collection parente.
4. Éditeur -> Serveur : `POST /api/v1/collections` avec :
   - `parent_id` de la collection partagée
   - `vxcm` (**métadonnées de collection** chiffrées)
   - `vxck_editor` (clé encapsulée à **étendue éditeur**)
   - `vxsh_owner` (**invitation X-Wing** pour le propriétaire)
5. Le serveur **DOIT** vérifier que le partage de l'éditeur sur la collection parente a le bit `edit` (`0x02`) défini dans `permission` avant d'accepter la requête. Rejeter avec `HTTP 403` sinon.
6. Le serveur stocke la nouvelle ligne de collection avec `user_id = editor_user_id` temporairement et insère une ligne dans `pending_ownership_transfers`.
7. Le serveur notifie le propriétaire via sync qu'un transfert en attente requiert son approbation.

### 21.2 Flux d'acceptation par le propriétaire

> Si le propriétaire a **l'acceptation automatique** activée dans les paramètres de son compte, le client **DOIT** traiter automatiquement tous les transferts en attente à la synchronisation sans inviter l'utilisateur. Les étapes 1-5 s'exécutent de manière identique ; aucune interface de confirmation n'est affichée.
>
> **Sémantique de la colonne `auto_accept` :** La colonne `auto_accept` sur `pending_ownership_transfers` capture la valeur du paramètre `auto_accept_subcollections` du propriétaire **au moment où la ligne de transfert est créée** dans la même transaction. Si le propriétaire modifie son paramètre après la création, la valeur capturée sur la ligne régit ce transfert spécifique.
>
> La valeur en direct de `users.auto_accept_subcollections` ne régit que les transferts futurs. Cela évite une situation de compétition où le propriétaire désactive l'acceptation automatique entre la création et le traitement par sync.

À la prochaine synchronisation, le **client du propriétaire de la collection parente** détecte le transfert en attente :

1. Le propriétaire récupère `vxsh_owner` depuis la ligne `pending_ownership_transfers`.
2. Le propriétaire vérifie la **signature ML-DSA-65** sur l'invitation de partage.
3. Le propriétaire désencapsule le texte chiffré **X-Wing**, dérive `shareWrapKey`, désencapsule `collectionKey`.
4. Le propriétaire encapsule `collectionKey` sous sa propre `masterKey` -> nouveau blob `VXCK` (étendue propriétaire).
5. Propriétaire -> Serveur : `POST /api/v1/collections/{collection_id}/accept-ownership` avec `vxck_owner`.
6. Le serveur procède de manière atomique :
   - Remplace `collections.user_id` par le `user_id` du propriétaire de la collection parente.
   - Stocke le `VXCK` à étendue propriétaire dans `collection_keys`.
   - Conserve le `VXCK` à étendue éditeur dans `collection_keys`. L'éditeur conserve l'accès cryptographique tant que son partage `edit` sur la collection parente reste valide.
   - Supprime la ligne `pending_ownership_transfers`.

### 21.3 Flux de rejet par le propriétaire

Si le propriétaire rejette explicitement le transfert :

1. Propriétaire -> Serveur : `POST /api/v1/collections/{collection_id}/reject-ownership`.
2. Le serveur procède de manière atomique :
   - Supprime définitivement la ligne de la sous-collection.
   - Supprime tous les `files`, `file_keys`, `collection_keys`, et blobs de stockage objet appartenant à la sous-collection. Les fichiers téléversés par l'éditeur pendant la fenêtre en attente sont inclus dans cette suppression.
   - Supprime la ligne `pending_ownership_transfers`.
3. Le serveur notifie l'éditeur via sync que la sous-collection a été rejetée. Le client de l'éditeur **DOIT** expulser la `collectionKey` de son cache Worker à la réception de cette notification.

### 21.4 Révocation de partage pendant un transfert en attente

Si le partage de l'éditeur sur la collection parente est révoqué alors qu'un transfert de propriété est en attente pour une sous-collection qu'il a créée, la révocation prend effet **immédiatement** au niveau de l'API. L'éditeur perd immédiatement l'accès à la collection parente. La résolution du transfert en attente est indépendante et se déroule comme suit :

1. Le serveur révoque le partage de manière atomique et définit `revocation_pending = TRUE` sur toutes les lignes `pending_ownership_transfers` initiées par cet éditeur sous la collection parente affectée.
2. Le serveur notifie le propriétaire via sync à la fois de la révocation et de tout transfert en attente nécessitant une résolution.
3. Le propriétaire **DEVRAIT** explicitement accepter ou rejeter chaque transfert en attente. Le serveur **DOIT** les présenter comme une décision groupée : `"L'accès de l'éditeur X a été révoqué. Il a créé N sous-collections en attente de votre approbation. Acceptez ou rejetez chacune avant de continuer."`
4. Si le propriétaire n'agit pas dans le TTL, le serveur rejette automatiquement tous les transferts en attente de cet éditeur, supprime atomiquement les sous-collections et leur contenu, et notifie le propriétaire via sync.
5. Si le propriétaire est hors ligne indéfiniment, le TTL garantit que l'état en attente ne persiste pas éternellement. La révocation du partage parent est déjà pleinement en vigueur indépendamment de l'expiration du TTL.

### 21.5 TTL de la fenêtre en attente

Si le transfert reste en attente au-delà du TTL configurable par l'opérateur (**recommandé** : *7 jours*) **sans action du propriétaire**, le serveur le **rejette automatiquement**, **supprime atomiquement la sous-collection et tout son contenu**, et notifie l'éditeur via sync.

> Le serveur **DOIT** notifier le propriétaire via sync **au moins 24 heures** avant l'expiration d'un transfert en attente. Si le propriétaire **n'agit pas après l'avertissement**, le transfert **est rejeté et la sous-collection supprimée** normalement.

### 21.6 Ajouts au schéma

```sql
CREATE TABLE pending_ownership_transfers (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collection_id      UUID NOT NULL REFERENCES collections(id)
                           ON DELETE RESTRICT,
    editor_user_id     UUID NOT NULL REFERENCES users(id)
                           ON DELETE RESTRICT,
    owner_user_id      UUID NOT NULL REFERENCES users(id)
                           ON DELETE RESTRICT,
    vxsh_owner         BYTEA NOT NULL,
    revocation_pending BOOLEAN NOT NULL DEFAULT FALSE,
    auto_accept        BOOLEAN NOT NULL DEFAULT FALSE,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL DEFAULT now() + INTERVAL '7 days'
);

CREATE UNIQUE INDEX ON pending_ownership_transfers (collection_id);
CREATE INDEX ON pending_ownership_transfers (owner_user_id)
    WHERE revocation_pending = FALSE;
CREATE INDEX ON pending_ownership_transfers (owner_user_id)
    WHERE revocation_pending = TRUE;
CREATE INDEX ON pending_ownership_transfers (expires_at);

-- POUR LA TABLE users !
ALTER TABLE users ADD COLUMN auto_accept_subcollections BOOLEAN NOT NULL DEFAULT FALSE;
```

`ON DELETE RESTRICT` sur toutes les clés étrangères garantit que les collections, éditeurs et propriétaires impliqués dans un transfert en attente ne peuvent pas être supprimés tant que le transfert n'est pas explicitement résolu. Les flux de suppression de compte **DOIVENT** résoudre ou rejeter tous les transferts en attente avant de supprimer la ligne utilisateur, conformément au parcours de dépendances défini au §19.3.

### 21.7 Note sur la vie privée

Pendant la fenêtre en attente, seul l'éditeur détient la `collectionKey` en clair. Le propriétaire de la collection parente n'a pas d'accès cryptographique à la sous-collection avant l'acceptation. Cette fenêtre devrait être gardée aussi courte que possible. Les clients **DEVRAIENT** traiter les transferts de propriété en attente de manière proactive à la synchronisation plutôt que de les différer.

L'interface **DOIT** afficher un indicateur `« En attente d'approbation du propriétaire »` sur la sous-collection pour l'éditeur, et un indicateur `« En attente de votre approbation »` pour le propriétaire.

### 21.8 Garanties

| Propriété                                                                              | Statut                                                                                                |
|----------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------|
| L'éditeur dispose d'un accès immédiat après la création                                | ✅                                                                                                    |
| Le propriétaire dispose d'un accès cryptographique avant l'acceptation                 | ❌ Fenêtre en attente                                                                                 |
| Le propriétaire devient le vrai propriétaire après acceptation                         | ✅                                                                                                    |
| Le propriétaire reçoit des permissions complètes sur la sous-collection acceptée       | ✅ `"p" = 0x07` appliqué dans `vxsh_owner`                                                            |
| Le propriétaire peut accepter automatiquement les transferts sans approbation manuelle | ✅ Paramètre opt-in par compte                                                                        |
| Le serveur peut lire le contenu de la sous-collection                                  | ❌ Connaissance zéro préservée                                                                        |
| Le transfert est authentifié cryptographiquement                                       | ✅ Signature ML-DSA-65 sur `vxsh_owner`                                                               |
| L'éditeur conserve l'accès après le transfert de propriété                             | ✅ Tant que son partage `edit` sur la collection parente reste valide                                 |
| Les fichiers téléversés pendant la fenêtre en attente sont supprimés en cas de rejet   | ✅                                                                                                    |
| La révocation du partage parent prend effet immédiatement                              | ✅ Indépendant de la résolution du transfert en attente                                               |
| Le transfert en attente est résolu avant la suppression du compte                      | ✅ `ON DELETE RESTRICT` appliqué, parcours de dépendances [§19.3](./CRYPTO.md#193-account-deletion)   |
| L'état en attente ne peut pas persister indéfiniment si le propriétaire est hors ligne | ✅ Rejet automatique par TTL après 7 jours                                                            |
| Le serveur rejette la création si l'éditeur manque la permission `edit`                | ✅ HTTP 403 sur bit `0x02` manquant                                                                   |
