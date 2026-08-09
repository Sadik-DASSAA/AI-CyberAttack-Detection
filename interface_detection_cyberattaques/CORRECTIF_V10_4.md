# Correctif v10.4 — lancement réellement en un clic

Cette version corrige le dernier blocage observé sous Windows à l'étape
`[5/6]` alors que Caddy, l'API et le Dashboard étaient déjà actifs.

## Cause

`curl.exe` utilise Schannel sous Windows. L'autorité Caddy locale ne publie pas
de serveur Internet de révocation, donc Schannel renvoyait
`CRYPT_E_NO_REVOCATION_CHECK` même lorsque la chaîne TLS et le nom `localhost`
étaient valides.

## Corrections

- validation TLS avec `--ssl-revoke-best-effort`, sans HTTP ni `--insecure` ;
- installation de l'autorité Caddy dans `CurrentUser\Root` et
  `LocalMachine\Root` ;
- gestion correcte du message de progression `docker compose cp` ;
- création automatique de `threshold.config` s'il manque dans Suricata ;
- vérification préalable de tous les fichiers nécessaires à Docker ;
- suppression du dépôt des comptes SQLite, sessions et certificats runtime ;
- contrôle du paquet modèle, de son mapping de classes et du scaler MinMax.

Le seul bouton de démarrage reste `LANCER_TOUT.bat`. Les comptes, historiques,
alertes, `.env` et volumes Docker déjà présents sur le poste sont conservés.
