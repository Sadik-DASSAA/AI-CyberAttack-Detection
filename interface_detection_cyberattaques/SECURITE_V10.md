# Sécurité de la plateforme - version 10.3

## Objectif

La v10 durcit la plateforme locale sans modifier la chaîne de détection déjà
validée : Wi-Fi, Npcap, Suricata, `eve.json`, API FastAPI et dashboard.

## Protections ajoutées

- CORS limité à `https://localhost` et validation des noms d'hôte de l'API ;
- en-têtes HTTP de sécurité et documentation interactive désactivée par défaut ;
- première inscription réservée au compte administrateur principal, puis
  fermeture automatique de l'inscription publique ;
- limitation des échecs de connexion enregistrée dans SQLite et conservée
  après les redémarrages ;
- récupération du mot de passe par code e-mail et changement depuis le profil ;
- fermeture de toutes les sessions après une modification du mot de passe ;
- journal des événements de sécurité du compte conservé pendant 90 jours ;
- isolation des historiques et des statistiques par identifiant utilisateur ;
- alertes Suricata automatiques attribuées au compte administrateur principal ;
- envoi d'une alerte uniquement à l'adresse vérifiée du propriétaire ;
- validation de l'extension, du nom, du contenu vide et de la taille des imports ;
- conteneurs applicatifs non privilégiés, systèmes de fichiers racine en lecture
  seule et capacités Linux supprimées ;
- passerelle HTTPS locale avec certificat de confiance, HSTS et adresse
  `https://localhost/SCA/` ;
- seul le port HTTPS `443` est publié sur `127.0.0.1`; les ports API `8000` et
  dashboard `8501` restent privés au réseau Docker ;
- remise à zéro du volume protégée par authentification, isolée par utilisateur
  et enregistrée dans le journal de sécurité ;
- volumes Docker privés et inscriptibles limités aux comptes et à l'historique,
  avec import automatique des données v9/v10 et sauvegarde locale à l'arrêt ;
- le dashboard ne reçoit plus les variables Gmail et le projet complet n'est
  plus monté dans les conteneurs.

## Limites configurées

| Élément | Valeur par défaut |
|---|---:|
| Session | 12 heures |
| Code e-mail | 10 minutes |
| Essais du code | 5 |
| Renvoi du code | 60 secondes |
| Échecs de connexion | 5 par identifiant/client sur 5 minutes |
| Import CSV | 200 Mo |
| Import EVE JSON | 64 Mo |

## Migration depuis la v9 ou la v10

Les comptes, l'historique et les alertes existants sont conservés. Au premier
démarrage, les dossiers locaux `security` et `history` sont importés dans les
volumes privés. Le premier compte existant devient administrateur principal.
Les lignes historiques sans propriétaire lui sont attribuées. Les nouveaux
événements sont ensuite isolés par utilisateur. `ARRETER_TOUT.bat` remet aussi
une sauvegarde courante dans les deux dossiers locaux.

## Validation

Le script `tests/test_security_v10.py` vérifie l'authentification, CORS,
TrustedHost, les en-têtes, les imports, l'isolation de deux comptes, la
récupération et le changement du mot de passe, le blocage persistant et le
journal d'audit. `tests/test_https_routing_v10_3.py` contrôle le chemin `/SCA/`,
l'absence d'exposition directe des ports applicatifs et le bouton de remise à
zéro.

Le 9 août 2026, les tests v10 et le test de migration v10.1 ont réussi. L'audit
des dépendances déclarées avec
`pip-audit` n'a signalé aucune vulnérabilité connue.

## Portée du verdict

Cette version est durcie pour une utilisation locale et pour la démonstration
du projet de stage. Elle ne constitue ni une certification, ni une garantie de
sécurité à 100 %, ni une autorisation de déploiement direct sur Internet. Un
déploiement public exigerait notamment un nom de domaine et un certificat
public, une gestion centralisée des secrets, des sauvegardes chiffrées, une
supervision externe et un test d'intrusion indépendant.
