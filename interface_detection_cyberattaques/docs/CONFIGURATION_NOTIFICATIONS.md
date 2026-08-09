# Configuration des notifications Gmail et SMS

## 1. Installation

Dans PowerShell, placez-vous dans le dossier du projet puis executez :

```powershell
python -m pip install -r requirements.txt
```

## 2. Creer le fichier `.env`

Copiez `.env.example` en `.env` :

```powershell
Copy-Item .env.example .env
```

Le fichier `.env` contient les secrets et ne doit pas etre publie sur GitHub.

## 3. Gmail

1. Activez la validation en deux etapes du compte Google.
2. Creez un mot de passe d'application Google de 16 caracteres.
3. Completez dans `.env` :

```text
GMAIL_ENABLED=true
GMAIL_SENDER=votre.adresse@gmail.com
GMAIL_RECIPIENT=destinataire@gmail.com
GMAIL_APP_PASSWORD=xxxx xxxx xxxx xxxx
```

Le mot de passe normal du compte Gmail ne doit pas etre utilise.

## 4. SMS avec Twilio

1. Creez un compte Twilio et obtenez un numero d'envoi SMS.
2. Copiez l'Account SID et l'Auth Token depuis la console Twilio.
3. Completez dans `.env` :

```text
SMS_ENABLED=true
TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TWILIO_AUTH_TOKEN=votre_auth_token_twilio
TWILIO_FROM_NUMBER=+1xxxxxxxxxx
SMS_RECIPIENT=+2126XXXXXXXX
```

Les numeros doivent utiliser le format international E.164. Avec un compte Twilio d'essai, le numero destinataire doit d'abord etre verifie dans Twilio.

## 5. Demarrage et test

Relancez FastAPI apres toute modification du fichier `.env` :

```powershell
uvicorn api:app --reload --port 8000
```

Dans un autre terminal :

```powershell
python -m streamlit run app.py
```

Ouvrez ensuite la page **Notifications**. Les etats Gmail et SMS doivent afficher `Configure`. Utilisez le bouton **Envoyer une notification de test** avant d'analyser un fichier complet.

Pendant une analyse CSV ou Suricata, choisissez Gmail, SMS ou les deux. Une notification est envoyee automatiquement pour chaque attaque detectee (`classe != BENIGN`). Le resultat de chaque envoi est conserve dans l'historique.
