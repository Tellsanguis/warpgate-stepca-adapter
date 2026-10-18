# Tests d'intégration

`make integration` (depuis la racine) lance `run.sh` qui, entièrement dans Docker :

1. génère des secrets jetables (`integration/gen`) : provisioner JWK, TLS, jeton, configuration ;
2. démarre un **vrai step-ca** (image de production épinglée) sur un réseau Docker `--internal` (aucun accès à Internet ni à l'hôte) ;
3. y ajoute le provisioner `warpgate-ops` et son modèle SSH à principal fixe `ops` (édition de `ca.json` puis redémarrage) ;
4. lance l'image de l'adaptateur en mode durci (lecture seule, sans capacités, `no-new-privileges`, 128 Mo) ;
5. exécute `integration_test.go` (étiquette `integration`) depuis un conteneur Go du même réseau ;
6. supprime conteneurs, réseau et fichiers.

Variable utile : `WORK_ROOT` (dossier des fichiers temporaires, `/tmp` par défaut).

Écart avec la production : l'adaptateur tourne avec l'UID de l'utilisateur courant pour lire les secrets en 0600 (en production, Podman `keep-id` joue ce rôle).

Jamais de connexion à une CA de production.

## Bout en bout (`make e2e`)

En plus des étapes ci-dessus : image `integration/sshd` (sshd Alpine qui n'accepte que les certificats de la CA de test, journal VERBOSE), **Warpgate 0.30.0 réel** (image épinglée par digest, lecture seule, sans capacités) configuré par son API d'administration, puis `integration/e2e/e2e_test.go`. `run.sh` vérifie ensuite dans les journaux :

- sshd : au moins deux `Accepted publickey for ops ... ED25519-CERT ... ID warpgate:admin:<session> ... CA ...` et aucune acceptation pour `postgres` ou `root` ;
- adaptateur : refus `principal_interdit` et `jeton_ou_role_refuse`, jeton absent des journaux ;
- puis arrêt de l'adaptateur : la session doit échouer et sshd ne doit enregistrer aucune connexion de plus.

`WG_BACKEND_SKIP_VERIFY=1` est le défaut (limite de Warpgate : pas de CA privée pour son client Vault).
