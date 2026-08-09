# Correctif v10.1 — persistance SQLite

## Problème corrigé

La v10 pouvait arrêter l'API au démarrage avec :

```text
sqlite3.OperationalError: attempt to write a readonly database
```

Le fichier SQLite provenait de la v9 et était monté depuis Windows avec des
droits incompatibles avec l'utilisateur non-administrateur du conteneur v10.
SQLite ne pouvait donc pas créer ses fichiers `-wal` et `-shm`.

## Correction appliquée

- l'API reste exécutée avec l'utilisateur non-root `10001:10001` ;
- la racine des conteneurs reste en lecture seule ;
- seuls `security` et `history` disposent de volumes Docker inscriptibles ;
- le premier lancement importe automatiquement les comptes et historiques
  existants ;
- `ARRETER_TOUT.bat` recopie les données courantes dans les dossiers locaux
  `security` et `history` ;
- `docker compose down` ne supprime pas les volumes persistants.

Ne lancez jamais `docker compose down -v`, car l'option `-v` supprime les
volumes. Le lanceur fourni n'utilise pas cette option.
