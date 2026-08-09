# Correctif v10.3.3 — contrôle HTTPS fiable

## Problème corrigé

La v10.3.2 lançait correctement Suricata, l'API, le dashboard et Caddy, mais le
lanceur pouvait rester bloqué à l'étape `[5/6]`. Le contrôle HTTPS reposait sur
la session PowerShell déjà ouverte, qui ne prenait pas toujours immédiatement
en compte le nouveau certificat racine. Après cinq minutes, le lanceur signalait
donc une erreur alors que les services continuaient à fonctionner.

Caddy tentait aussi d'installer son certificat dans son propre conteneur en
lecture seule. Cette tentative inutile produisait le message
`failed to execute tee`, sans empêcher la passerelle de servir HTTPS.

## Correction

- le certificat racine Caddy est toujours copié, validé et approuvé par Windows ;
- la sonde de santé vérifie `https://localhost/SCA/_stcore/health` avec ce
  certificat exact via `curl.exe --cacert` ;
- aucun contournement `--insecure` n'est utilisé ;
- Caddy utilise les options globales `local_certs` et `skip_install_trust`, sans
  directive `tls internal` propre au site, afin de ne plus tenter d'écrire dans
  le magasin de confiance de son conteneur ;
- l'URL publique reste uniquement `https://localhost/SCA/`.

Les comptes, historiques, alertes, modèles, volumes Docker et certificats
existants sont conservés.
