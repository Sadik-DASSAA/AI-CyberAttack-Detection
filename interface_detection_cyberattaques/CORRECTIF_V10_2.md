# Correctif v10.2 — synchronisation authentifiée du tableau de bord

## Symptôme corrigé

Le compte était connecté et la page Alertes affichait des événements, mais les
widgets du tableau de bord restaient vides. Les appels `Historique`,
`Statistiques`, `Modèle` et `Notifications` renvoyaient tous `HTTP 401`.

## Cause

Les quatre appels étaient exécutés dans des threads secondaires. Chacun tentait
de relire directement le jeton dans `st.session_state`, alors que cet état
Streamlit doit être consulté depuis le thread principal.

## Correction

Le jeton est désormais lu une seule fois dans le thread principal. Une copie de
l'en-tête `Authorization` est transmise explicitement aux quatre requêtes
parallèles. Le bloc visuel « Diagnostic de synchronisation » a également été
retiré.

Ce correctif ne modifie ni les comptes, ni l'historique, ni les alertes, ni la
configuration Suricata.
