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
- Le certificat renvoyé ne porte que l'extension `permit-pty` : toute autre (forwarding de port, d'agent, X11, `permit-user-rc`) est refusée. Le modèle SSH du provisioner doit donc n'émettre que celle-là.
- Le modèle SSH du provisioner (côté CA) garde le dernier mot sur les principals, même si l'adaptateur était compromis (prouvé par un test contre une vraie CA).
- Échec fermé : toute anomalie de configuration, de CA ou de clé arrête le démarrage.
- Connexions simultanées plafonnées au total (`max_conns`, 128 par défaut) et par IP source (`max_conns_per_ip`, 32) : au-delà, la connexion est fermée tout de suite, les connexions déjà établies ne sont jamais coupées.
- Quota de signatures **par jeton** (`rate_per_minute`, 60 par défaut) : un client bavard ne prive pas les autres.
- Le certificat TLS de l'adaptateur est relu quand ses fichiers changent (renouvellement Let's Encrypt) : pas de redémarrage. Un nouveau fichier invalide est journalisé et l'ancien certificat reste servi.

## Commandes (tout passe par Docker, rien n'est installé sur l'hôte)

```bash
make init-cache     # une fois: volume de cache Go
make test           # tests unitaires avec détecteur de courses
make fuzz           # fuzzing de l'analyse des requêtes et de la vérification du certificat de la CA (30 s par cible)
make integration    # vrai step-ca éphémère + adaptateur durci (voir integration/README.md)
make e2e            # + Warpgate 0.30.0 réel et une cible sshd (Docker local, réseau interne)
make security       # tout: format, vet, tests, fuzz, govulncheck, staticcheck, gosec, hadolint, trivy
make build          # image warpgate-stepca-adapter:dev (environ 18 Mo, sans shell, non root)
make demo          # environnement à essayer à la main : navigateur et ssh (voir « Essayer à la main »)
make strix          # passe Strix (clé de modèle requise)
```

## Essayer à la main (`make demo`)

`make demo` démarre en Docker local, sur votre machine uniquement : step-ca éphémère, l'adaptateur, **Warpgate 0.30.0**, une cible sshd qui n'accepte que les certificats de la CA de test, puis configure Warpgate (backend de secrets, rôle, quatre cibles). Seuls deux ports sont ouverts, **sur 127.0.0.1** : 8888 (web) et 2222 (SSH). Un cadre affiche l'adresse, l'identifiant `admin` et un mot de passe aléatoire. **Ctrl+C supprime tout** (conteneurs, réseaux, volumes, secrets).

1. **Navigateur** : `https://localhost:8888/@warpgate` (certificat auto-signé : accepter l'avertissement). Depuis Windows avec WSL2, `localhost` est transmis automatiquement. Se connecter avec `admin`. Dans la liste des cibles, ouvrir `sshd-target` : Warpgate ouvre un terminal dans le navigateur. Taper `id` : le compte est `ops`. L'administration (`/@warpgate/admin`) montre les sessions avec **l'enregistrement rejouable**, et `Config > Secret backends` la santé de l'adaptateur.
2. **Terminal SSH** : `ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null admin:sshd-target@localhost` (même mot de passe). Warpgate demande un certificat à l'adaptateur, qui le fait signer par step-ca, puis se connecte à la cible avec.
3. **Cibles qui doivent échouer** : `sshd-badprincipal` (compte hors liste blanche), `sshd-forbiddenrole` (rôle refusé à ce jeton), `sshd-blockedpath` (chemin interdit côté Warpgate). La connexion se ferme sans rien afficher.
4. **Voir la preuve** dans un autre terminal (les noms exacts sont dans le cadre affiché) : le journal de sshd contient `Accepted publickey for ops ... ED25519-CERT ... ID warpgate:admin:<session> ... CA ...`, et celui de l'adaptateur une ligne `"event":"sign"` par session avec l'empreinte de la clé (jamais la clé complète).

Limites de la démo : certificats de test auto-signés (donc `tls_skip_verify` côté Warpgate), et pas de SSO. Pour changer les ports : `DEMO_HTTP_PORT=18888 DEMO_SSH_PORT=12222 make demo`.

## Mise en place

1. Dans step-ca : provisioner JWK dédié et modèle SSH à principal fixe (voir `../Warpgate/docs/pr-ansible-stepca.md`).
2. Configuration : `deploy/config.example.json`. Le fichier JWK chiffré et son mot de passe sont les secrets du provisioner (modes 0600 exigés).
3. Générer un jeton long et aléatoire pour Warpgate ; seule son empreinte va dans la configuration (`printf %s "$JETON" | sha256sum`).
4. Warpgate : ajouter un backend de secrets Vault pointant vers `https://<hôte>:8200` avec ce jeton, limiter les chemins autorisés à `ssh/sign/<rôle>`, et déclarer les cibles SSH en authentification par certificat avec ce rôle.
5. Déploiement : `deploy/warpgate-stepca-adapter.container.example` (Quadlet, non testé avec Podman).

## Durées : le minimum de 5 minutes de step-ca

step-ca refuse tout certificat SSH plus court que `minUserSSHCertDuration` (5 minutes par défaut, valeur des claims de la CA de production). Warpgate 0.30.0 demande toujours `ttl = 5m` (constante dans son code). Les trois valeurs doivent donc rester cohérentes :

| Réglage | Contrainte |
|---|---|
| Claims du provisioner step-ca | `minUserSSHCertDuration` ≤ 5 min ≤ `maxUserSSHCertDuration` |
| `max_ttl` du rôle de l'adaptateur | ≥ 5 min (10 min recommandé) et ≤ 1 h (plafond du code) |
| `ttl` demandé par le client | entre 5 min et `max_ttl` |

Si `max_ttl` est inférieur au minimum de la CA, ou si un client demande moins, la CA refuse et l'adaptateur répond 502 « upstream error » (le détail est dans le journal, champ `detail`). L'adaptateur ne connaît pas les claims de la CA et ne peut pas le détecter au démarrage.

## Certificat TLS de l'adaptateur : Let's Encrypt

Pour le HTTPS, utiliser un certificat Let's Encrypt (comme pour le reste de vos services web) et non un certificat step-ca : **Warpgate 0.30.0 ne vérifie que les racines publiques** (voir « Constats »). Avec Let's Encrypt, Warpgate peut vérifier le certificat de l'adaptateur et `tls_skip_verify` doit rester à **faux** en production. Conditions :

- un nom DNS public pour l'adaptateur (défi DNS-01 si l'hôte n'est pas joignable depuis Internet) ; le nom figure dans les journaux de transparence des certificats ;
- `address` du backend dans Warpgate = ce nom (pas l'IP) ;
- le client ACME écrit `tls_cert` (chaîne complète) et `tls_key` ; l'adaptateur relit les fichiers dès que leur date de modification change. Le fichier de clé doit rester lisible par l'utilisateur de l'adaptateur et de lui seul (0600) : si le client ACME l'écrit en `root:root 0600`, prévoir un hook de déploiement qui installe une copie pour l'adaptateur ;
- `ca.url` et `ca.root_file` (vers step-ca) restent sur la racine **step-ca** : Let's Encrypt n'intervient que pour l'écoute de l'adaptateur.

## Exploitation et choix assumés

| Sujet | Comportement | Conséquence pour l'exploitation |
|---|---|---|
| Rotation de la CA SSH de step-ca | Les clés CA SSH sont lues au démarrage et épinglées. Après rotation, les certificats arrivent signés par une clé inconnue : refus (échec fermé, 502), jamais d'acceptation par erreur. | Ajouter « redémarrer l'adaptateur » à la procédure de rotation, qui de toute façon impose de mettre à jour `TrustedUserCAKeys` sur toutes les VMs. |
| Quota de signatures | Par jeton, fenêtre fixe d'une minute (rafale possible jusqu'à 2 fois le quota à la jonction de deux fenêtres). | Dimensionner `rate_per_minute` au nombre de sessions SSH par minute attendu pour ce client. |
| Limiteur d'échecs d'authentification | Global (30 par minute), non lié à l'IP. Après 30 échecs, les refus répondent 429 au lieu de 403 ; les requêtes valides ne sont jamais bloquées. | Seul Warpgate doit pouvoir joindre le port (nftables, FortiGate). Si le filtrage est en place, un 429 ne peut venir que d'un Warpgate mal configuré (jeton ou rôle erroné) : c'est visible dans le journal (`trop_d_echecs`). |
| `ttl` en secondes nues (`"300"`) | Refusé : seule une durée Go (`5m`) est acceptée. | Warpgate envoie `5m`. Un autre client Vault devrait être adapté. |
| Clés JSON dupliquées dans la requête | La dernière valeur est retenue (comportement de `encoding/json`), sans erreur. | Sans conséquence ici : l'adaptateur valide et signe la même valeur finale (liste blanche de principals), et l'accès d'un utilisateur est fixé par ses rôles Warpgate (un rôle = une cible = un rôle de signature), pas par le corps de la requête. Le risque n'existerait que si un intermédiaire validait une autre version du même JSON ; il n'y en a pas. |
| Durée minimale | Voir la section précédente. | Cohérence entre claims step-ca, `max_ttl` et `ttl` demandé. |
| Écoute | `listen` est validé (hôte:port, port 1 à 65535). Avec `Network=host`, préférer une IP précise à `:8200`. | La sonde de santé vise l'adresse d'écoute réelle. |

## Dépendances

`github.com/go-jose/go-jose/v4` (jeton JWK, déchiffrement du JWE de `ca.json`) et `golang.org/x/crypto/ssh`. Le reste est la bibliothèque standard.

## Constats du bout en bout avec Warpgate 0.30.0

1. **Warpgate ne peut pas vérifier le certificat TLS d'une CA privée** (il vérifie sans problème un certificat Let's Encrypt, voir plus haut). Son client Vault embarque des racines publiques, vide `ca_certs` et n'offre aucune option de CA (ni `SSL_CERT_FILE`, ni magasin système). Vers l'adaptateur il faut donc `tls_skip_verify`. Le test `TestKnownLimitationWarpgateCannotTrustPrivateCA` fige ce constat et échouera le jour où Warpgate ajoutera l'option. Voir « Risques résiduels » du modèle de menaces pour les parades.
2. **Warpgate n'envoie aucun `Content-Type`** (comme avec un vrai Vault). L'adaptateur accepte donc l'absence de type et refuse tout autre type que `application/json`.
3. **Warpgate exige une route par défaut ou `WARPGATE_PEER_ADDRESS`** : il résout son adresse de pair par un `connect` UDP vers 1.1.1.1 et s'arrête avec « Network is unreachable » sur un réseau Docker interne. Positionner `WARPGATE_PEER_ADDRESS=hôte:port`.
4. L'écoute IPv6 par défaut (`::`) échoue sur un réseau sans IPv6 : `--listen-address 0.0.0.0` à l'initialisation.

Assisté par Claude Code.
