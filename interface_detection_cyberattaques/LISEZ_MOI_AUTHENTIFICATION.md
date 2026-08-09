# Authentification et verification de l'e-mail

## Fonctionnement

La plateforme demande une authentification avant d'afficher le
dashboard, les analyses, les alertes ou l'historique.

L'inscription se déroule en deux étapes :

1. l'utilisateur renseigne son nom, son identifiant, son mot de passe et
   l'adresse e-mail qui recevra les alertes ;
2. la plateforme envoie un code à 6 chiffres et ne crée le compte qu'après la
   saisie du code correct.

Le code expire après 10 minutes, accepte au maximum 5 essais et ne peut pas
être renvoyé immédiatement. Le mot de passe n'est jamais enregistré en clair.

## Configuration Gmail requise

Le fichier `.env` déjà utilisé pour les alertes doit contenir :

```text
GMAIL_ENABLED=true
GMAIL_SENDER=votre.adresse@gmail.com
GMAIL_APP_PASSWORD=xxxx xxxx xxxx xxxx
GMAIL_SMTP_HOST=smtp.gmail.com
GMAIL_SMTP_PORT=587
```

`GMAIL_APP_PASSWORD` doit être un mot de passe d'application Google et non le
mot de passe habituel du compte. Le fichier `.env.example` fourni sert de
modèle et ne contient aucun secret.

## Première inscription

1. Double-cliquez sur `LANCER_TOUT.bat`.
2. Ouvrez l'onglet **Inscription**.
3. Saisissez les informations du compte et l'e-mail d'alerte.
4. Cliquez sur **Recevoir le code de vérification**.
5. Consultez la boîte de réception, saisissez les 6 chiffres, puis cliquez sur
   **Vérifier et créer le compte**.

La session est ouverte automatiquement après la validation.

Par sécurité, la première inscription crée le compte administrateur principal.
L'inscription publique est ensuite fermée automatiquement. Elle ne doit être
réactivée que volontairement avec `AUTH_ALLOW_ADDITIONAL_REGISTRATION=true`.

## Mot de passe oublié ou changement du mot de passe

- Sur la page de connexion, ouvrez **Mot de passe oublié**, demandez le code,
  puis saisissez le code et le nouveau mot de passe.
- Dans **Profil sécurisé**, le mot de passe peut être changé après saisie du
  mot de passe actuel.
- Toute réinitialisation ou modification ferme les sessions existantes.

Les échecs de connexion sont comptabilisés dans la base locale pendant cinq
minutes. Cette protection persiste après un redémarrage de Docker.

## Changer l'adresse d'alerte

Dans **Profil sécurisé**, saisissez et confirmez la nouvelle adresse. L'ancienne
adresse reste active jusqu'à la validation du code envoyé à la nouvelle
adresse. Une adresse non vérifiée ne reçoit jamais les alertes.

## Conservation

Les comptes et sessions actifs sont stockés dans un volume Docker privé. Une
copie de sauvegarde est automatiquement écrite à l'arrêt dans :

```text
security\authentication.db
```

Ce fichier et son volume sont conservés lors de `ARRETER_TOUT.bat` et des
redémarrages Docker. N'utilisez pas `docker compose down -v`.

Les historiques et statistiques sont isolés par utilisateur. Les alertes
Suricata automatiques appartiennent uniquement au compte administrateur
principal et ne sont envoyées qu'à son adresse vérifiée.
