# Surveillance automatique de Suricata

Cette version remplace l'import répétitif de `eve.json` par une lecture continue.

## Fonctionnement

- Suricata reste lancé sous Windows et écrit dans `alerts\eve.json`.
- Docker monte le dossier `alerts` en lecture seule dans le service API.
- L'API vérifie les nouvelles lignes toutes les deux secondes.
- Seuls les événements `event_type: alert` sont qualifiés.
- Un curseur persistant reprend exactement à la dernière ligne lue.
- Un identifiant SHA-256 empêche l'enregistrement et la notification en double.
- Le premier démarrage se place à la fin du journal existant, car les anciennes
  alertes ont déjà été importées manuellement.

## Démarrage

Double-cliquer sur `LANCER_TOUT.bat`. Ce lanceur démarre Npcap, Suricata,
l'API et le dashboard, puis ouvre automatiquement le site. Le fichier
`demarrer.bat` redirige également vers ce lancement complet.

Pour arrêter toute la plateforme, double-cliquer sur `ARRETER_TOUT.bat`.

Le panneau doit afficher :

```text
Lecture automatique active
Lecteur EVE : Actif
Fichier surveillé : Détecté
```

## Test

Dans une deuxième fenêtre PowerShell :

```powershell
curl.exe --max-time 20 "http://testmynids.org/uid/index.html"
```

Dans les cinq secondes suivantes, la nouvelle alerte doit apparaître dans le
panneau **Dernières alertes Suricata** et dans le registre des incidents.

L'import manuel est conservé comme solution de secours. Les événements déjà
présents sont ignorés et ne déclenchent pas une nouvelle notification.
