# Version v10.3/v10.3.1 — remise à zéro du compteur et HTTPS local

## Nouveautés

- Bouton **Réinitialiser le volume** dans la carte du trafic analysé.
- Fenêtre de confirmation avant toute remise à zéro.
- Route API authentifiée `POST /metrics/traffic/reset`.
- Remise à zéro isolée par utilisateur, sans suppression de l'historique.
- Événement `traffic_volume_reset` ajouté au journal de sécurité.
- Adresse publique unique : `https://localhost/SCA/`.
- Suppression du paramètre technique `?version=...`.
- Suppression des publications directes des ports API `8000` et dashboard `8501`.
- Terminaison TLS locale par Caddy et en-têtes HTTP de sécurité.

## Certificat HTTPS

Au premier démarrage, Caddy génère une autorité locale dans un volume Docker.
Le lanceur copie uniquement son certificat public dans
`certificates/SCA-local-root.crt`, puis l'ajoute au magasin de confiance de
l'utilisateur Windows. La clé privée n'est jamais copiée hors du volume Docker.

Si l'autorité locale est régénérée, le lanceur remplace automatiquement l'ancien
certificat SCA qu'il avait installé.

## Données préservées

La mise à niveau ne supprime ni `.env`, ni les comptes, ni les adresses e-mail
vérifiées, ni `security`, ni `history`, ni `alerts`.

Ne jamais exécuter `docker compose down -v`, car cette option supprime les
volumes persistants, y compris l'autorité HTTPS locale.

## Correctif v10.3.1

La v10.3.1 autorise uniquement `NET_BIND_SERVICE` dans le conteneur Caddy. Cette
capacité est exigée par le binaire de l'image officielle au moment de son
exécution. Sans elle, Docker affiche `exec caddy failed: Operation not permitted`
et le lanceur reste bloqué à l'étape `[5/6]`.

Toutes les autres capacités restent supprimées. Le conteneur continue de
s'exécuter avec l'utilisateur non-root `10001`, le système de fichiers en
lecture seule et `no-new-privileges`.
