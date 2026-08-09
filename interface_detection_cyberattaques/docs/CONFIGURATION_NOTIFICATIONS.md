# Configuration des notifications Gmail

La version v10.4 envoie les codes de vérification et les alertes par Gmail.
L'ancien exemple Twilio/SMS a été retiré parce qu'aucune route SMS n'est
implémentée dans l'API actuelle.

## Créer le fichier local `.env`

Dans PowerShell, depuis le dossier de l'application :

```powershell
Copy-Item .env.example .env
notepad .env
```

Renseignez uniquement :

```text
GMAIL_ENABLED=true
GMAIL_SENDER=votre.adresse@gmail.com
GMAIL_APP_PASSWORD=xxxx xxxx xxxx xxxx
GMAIL_SMTP_HOST=smtp.gmail.com
GMAIL_SMTP_PORT=587
```

Le compte Google doit utiliser la validation en deux étapes et un mot de passe
d'application de 16 caractères. N'utilisez jamais le mot de passe normal du
compte Gmail.

Le destinataire n'est pas stocké dans `.env` : chaque compte reçoit les alertes
sur l'adresse vérifiée lors de son inscription.

## Appliquer la configuration

Après toute modification, relancez uniquement `LANCER_TOUT.bat`. Le fichier
`.env` est exclu de Git et ne doit jamais être envoyé ou publié.
