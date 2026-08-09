# Correctif v10.3.2 — initialisation fiable de HTTPS

## Problème corrigé

Après un premier lancement, Caddy protège les répertoires de sa PKI locale.
Lors du lancement suivant, `gateway-init` possédait le droit de changer le
propriétaire, mais pas celui de traverser tous ces répertoires privés pendant
son `chown -R`. L'initialisation échouait donc après l'arrêt propre de
l'ancienne passerelle. L'API et le dashboard restaient actifs, mais le
conteneur `gateway` demeurait arrêté et `https://localhost/SCA/` était
inaccessible.

## Correction

- `gateway-init` reçoit `DAC_OVERRIDE` et `FOWNER` en plus de `CHOWN` ;
- les volumes HTTPS sont préparés avant le démarrage de la passerelle non-root ;
- le lanceur vérifie que `gateway` est réellement actif ;
- en cas d'échec, les journaux de `gateway-init` et `gateway` sont affichés
  immédiatement au lieu de laisser une attente ambiguë.

Les comptes, l'historique, les alertes, le modèle et les certificats existants
ne sont ni supprimés ni réinitialisés.

Ces capacités supplémentaires sont limitées au conteneur d'initialisation : il
ne possède aucun accès réseau, s'exécute une seule fois, puis s'arrête. Le
conteneur `gateway` reste non-root et conserve uniquement
`NET_BIND_SERVICE`.
