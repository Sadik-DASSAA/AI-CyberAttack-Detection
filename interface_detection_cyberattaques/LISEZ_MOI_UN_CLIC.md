# Supervision des cyberattaques - lancement en un clic (v10.3.3 HTTPS)

La v10.3.3 conserve les correctifs SQLite et de synchronisation de la v10.2. Elle
ajoute un bouton authentifié permettant de remettre uniquement le volume de
trafic analysé à zéro et publie le site sous une adresse HTTPS locale propre :

```text
https://localhost/SCA/
```

Les ports directs du dashboard (`8501`) et de l'API (`8000`) ne sont plus
exposés sur Windows. Le paramètre technique `?version=...` a été supprimé.

Cette révision corrige aussi le démarrage de la passerelle HTTPS avec l'image
officielle Caddy. Le conteneur reste non-root, en lecture seule et limité au
réseau interne du projet.

Les comptes et l'historique existants sont importés automatiquement au premier
lancement, sans supprimer `security`, `history`, `.env` ou `alerts`.

Cette révision conserve la correction des DLL Suricata/Npcap, l'authentification
avec vérification de l'adresse e-mail et ajoute le durcissement de l'API, des
données et des conteneurs.

## Démarrer toute la plateforme

Double-cliquez uniquement sur :

```text
LANCER_TOUT.bat
```

Acceptez la demande Windows de droits administrateur. Le lanceur effectue
automatiquement les opérations suivantes :

1. démarre Docker Desktop s'il est fermé ;
2. démarre Npcap ;
3. détecte l'interface réseau, l'adresse IPv4 et `HOME_NET` ;
4. valide et lance Suricata dans une fenêtre dédiée ;
5. construit et démarre l'API, le dashboard et la passerelle HTTPS ;
6. installe dans le magasin Windows utilisateur le certificat local SCA ;
7. vérifie le modèle IA et la lecture automatique de `eve.json` ;
8. ouvre `https://localhost/SCA/` dans le navigateur.

La réussite est confirmée par le titre :

```text
SITE COMPLET OPERATIONNEL
```

Le certificat public est conservé dans `certificates/SCA-local-root.crt`. Sa clé
privée reste exclusivement dans le volume Docker HTTPS et n'est pas exportée.

Dans le tableau de bord, le bouton **Réinitialiser le volume** demande une
confirmation. Il remet seulement le compteur de flux du compte connecté à zéro.
Les alertes, attaques, incidents et journaux ne sont pas supprimés.

Au premier accès, ouvrez **Inscription**, saisissez vos informations et
l'adresse qui recevra les alertes, puis entrez le code à 6 chiffres reçu par
e-mail. Le compte n'est créé qu'après cette vérification.

Consultez `LISEZ_MOI_AUTHENTIFICATION.md` si l'envoi du code indique que Gmail
n'est pas configuré.

Ne fermez pas la fenêtre verte de Suricata pendant la surveillance. La fenêtre
du lanceur peut être fermée après le message de réussite.

## Arrêter toute la plateforme

Double-cliquez sur :

```text
ARRETER_TOUT.bat
```

Cet arrêt conserve les comptes, les adresses vérifiées, le modèle,
l'historique, `fast.log`, `eve.json` et `stats.log`. Les comptes et l'historique
restent dans leurs volumes Docker et sont également recopiés dans les dossiers
locaux `security` et `history`.

N'utilisez pas `docker compose down -v` : l'option `-v` supprime volontairement
les volumes persistants. Les lanceurs fournis n'utilisent jamais cette option.

## Test rapide

Lorsque le dashboard est ouvert, exécutez dans une autre fenêtre PowerShell :

```powershell
curl.exe --max-time 20 "http://testmynids.org/uid/index.html"
```

L'alerte `GPL ATTACK_RESPONSE id check returned root` doit apparaître
automatiquement dans le dashboard en quelques secondes.

## Emplacements détectés automatiquement

Le dossier `outputs` peut se trouver à côté du lanceur ou dans son dossier
parent. Le dossier `alerts` peut également se trouver à côté du lanceur, dans
son dossier parent, ou à l'emplacement déjà utilisé sur ce PC :

```text
C:\Users\lorde\Downloads\Datasets\interface_detection_cyberattaques\alerts
```

Le fichier facultatif
`C:\ProgramData\Suricata\rules\lab-dashboard.rules` est chargé s'il existe.
Les règles ET Open restent actives dans tous les cas.
