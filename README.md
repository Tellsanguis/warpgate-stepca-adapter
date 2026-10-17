# warpgate-stepca-adapter

Petit service Go (environ 900 lignes hors tests, 5 fichiers) qui permet à **Warpgate** v0.30.0 d'obtenir des certificats SSH éphémères signés par **step-ca**, sans installer Vault ni OpenBao. Warpgate croit parler à un moteur SSH de Vault ; l'adaptateur traduit l'appel en demande de signature à step-ca.

```
Warpgate --HTTPS (TLS 1.3, jeton)--> adaptateur --HTTPS (racine épinglée, jeton JWK de 30 s)--> step-ca
   POST /v1/<mount>/sign/<rôle>                      POST /1.0/ssh/sign (provisioner JWK, modèle SSH)
   GET  /v1/auth/token/lookup-self                   GET  /1.0/ssh/roots
```

Contexte : `../Warpgate/docs/adaptateur-stepca.md` (spécification) et `security/threat-model.md` (menaces, contrôles et tests associés).

## Ce qui est garanti

- Authentification par jeton (empreinte SHA-256 en configuration), un jeton ne voit que ses rôles.
- Par rôle : provisioner step-ca, liste blanche de principals (un seul par certificat, jamais `root`), durée maximale.
- Ed25519 seulement, `key_id` obligatoirement préfixé `warpgate:`, requêtes strictes (champs inconnus refusés).
- Tout certificat renvoyé par la CA est **revérifié** avant d'être rendu : type, clé, key id, principals, expiration, signature par la clé CA connue.
- Le modèle SSH du provisioner (côté CA) garde le dernier mot sur les principals, même si l'adaptateur était compromis (prouvé par un test contre une vraie CA).
- Échec fermé : toute anomalie de configuration, de CA ou de clé arrête le démarrage.

## Commandes (tout passe par Docker, rien n'est installé sur l'hôte)

```bash
make init-cache     # une fois: volume de cache Go
make test           # tests unitaires avec détecteur de courses
make fuzz           # fuzzing de l'analyse des requêtes (30 s par cible)
make integration    # vrai step-ca éphémère + adaptateur durci (voir integration/README.md)
make e2e            # + Warpgate 0.30.0 réel et une cible sshd (Docker local, réseau interne)
make security       # tout: format, vet, tests, fuzz, govulncheck, staticcheck, gosec, hadolint, trivy
make build          # image warpgate-stepca-adapter:dev (environ 18 Mo, sans shell, non root)
make strix          # passe Strix (clé de modèle requise)
```

## Mise en place

1. Dans step-ca : provisioner JWK dédié et modèle SSH à principal fixe (voir `../Warpgate/docs/pr-ansible-stepca.md`).
2. Configuration : `deploy/config.example.json`. Le fichier JWK chiffré et son mot de passe sont les secrets du provisioner (modes 0600 exigés).
3. Générer un jeton long et aléatoire pour Warpgate ; seule son empreinte va dans la configuration (`printf %s "$JETON" | sha256sum`).
4. Warpgate : ajouter un backend de secrets Vault pointant vers `https://<hôte>:8200` avec ce jeton, limiter les chemins autorisés à `ssh/sign/<rôle>`, et déclarer les cibles SSH en authentification par certificat avec ce rôle.
5. Déploiement : `deploy/warpgate-stepca-adapter.container.example` (Quadlet, non testé avec Podman).

## Dépendances

`github.com/go-jose/go-jose/v4` (jeton JWK, déchiffrement du JWE de `ca.json`) et `golang.org/x/crypto/ssh`. Le reste est la bibliothèque standard.

## Constats du bout en bout avec Warpgate 0.30.0

1. **Warpgate ne peut pas vérifier le certificat TLS d'une CA privée.** Son client Vault embarque des racines publiques, vide `ca_certs` et n'offre aucune option de CA (ni `SSL_CERT_FILE`, ni magasin système). Vers l'adaptateur il faut donc `tls_skip_verify`. Le test `TestKnownLimitationWarpgateCannotTrustPrivateCA` fige ce constat et échouera le jour où Warpgate ajoutera l'option. Voir « Risques résiduels » du modèle de menaces pour les parades.
2. **Warpgate n'envoie aucun `Content-Type`** (comme avec un vrai Vault). L'adaptateur accepte donc l'absence de type et refuse tout autre type que `application/json`.
3. **Warpgate exige une route par défaut ou `WARPGATE_PEER_ADDRESS`** : il résout son adresse de pair par un `connect` UDP vers 1.1.1.1 et s'arrête avec « Network is unreachable » sur un réseau Docker interne. Positionner `WARPGATE_PEER_ADDRESS=hôte:port`.
4. L'écoute IPv6 par défaut (`::`) échoue sur un réseau sans IPv6 : `--listen-address 0.0.0.0` à l'initialisation.

Assisté par Claude Code.
