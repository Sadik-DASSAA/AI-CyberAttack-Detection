# Correctif v10.3.1 — démarrage de la passerelle HTTPS

## Problème corrigé

Le lancement pouvait rester à l'étape `[5/6]` avec le message suivant :

```text
[FATAL tini] exec caddy failed: Operation not permitted
```

L'image officielle Caddy attribue `NET_BIND_SERVICE` à son binaire. Docker
refuse son exécution si toutes les capacités sont retirées du conteneur, même
quand le service écoute sur le port interne non privilégié `8443`.

## Correction

La passerelle conserve uniquement `NET_BIND_SERVICE`, la capacité minimale
requise pour exécuter ce binaire. Les protections suivantes restent actives :

- utilisateur non-root `10001:10001` ;
- système de fichiers en lecture seule ;
- toutes les autres capacités supprimées ;
- `no-new-privileges` ;
- API et dashboard non exposés directement ;
- accès public limité à `https://localhost/SCA/`.

Le correctif ne modifie ni les comptes, ni l'historique, ni les alertes, ni le
certificat déjà enregistré dans le volume Docker.
