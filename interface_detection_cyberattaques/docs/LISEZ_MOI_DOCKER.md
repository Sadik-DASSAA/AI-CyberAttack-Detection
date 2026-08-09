# Docker et HTTPS — Supervision des cyberattaques v10.4

La plateforme utilise six services Compose :

- `data-init` migre une seule fois les comptes et l'historique locaux ;
- `api` exécute FastAPI sur le réseau Docker interne ;
- `dashboard` exécute Streamlit sous le chemin `/SCA/` ;
- `gateway-init` prépare les volumes Caddy ;
- `gateway` publie uniquement HTTPS sur `127.0.0.1:443` ;
- `data-export`, activé à l'arrêt, sauvegarde les données persistantes.

Les ports internes `8000` et `8501` ne sont pas publiés sur Windows. L'unique
adresse utilisateur est :

```text
https://localhost/SCA/
```

## Fichiers requis

```text
interface_detection_cyberattaques/
├── LANCER_TOUT.bat
├── ARRETER_TOUT.bat
├── demarrer_tout.ps1
├── arreter_tout.ps1
├── suricata_runtime.ps1
├── api.py
├── app.py
├── auth_security.py
├── data_migration.py
├── requirements.txt
├── Dockerfile
├── compose.yaml
├── Caddyfile
└── .dockerignore
```

Le modèle est monté en lecture seule depuis
`../outputs/modelisation_evaluation/models/meilleur_modele.pkl`.

## Utilisation

Double-cliquer uniquement sur `LANCER_TOUT.bat`. Le script démarre Docker
Desktop si nécessaire, valide et lance Suricata, construit les images, attend
l'API et le Dashboard, approuve l'autorité Caddy dans Windows, vérifie HTTPS et
ouvre le navigateur.

Pour arrêter et sauvegarder les comptes ainsi que l'historique, utiliser
`ARRETER_TOUT.bat`.

Ne jamais exécuter `docker compose down -v` : l'option `-v` supprime les
volumes persistants.

## Vérifications techniques

```powershell
docker compose ps
docker compose logs --tail=100 api dashboard gateway
```

`api`, `dashboard` et `gateway` doivent rester actifs. `data-init` et
`gateway-init` terminés avec le code 0 sont normaux : ce sont des tâches
ponctuelles.

## Données locales

`.env`, `security`, `history`, `certificates`, `.runtime` et `alerts/eve.json`
ne sont pas versionnés. Le certificat privé HTTPS reste exclusivement dans le
volume Docker Caddy.
