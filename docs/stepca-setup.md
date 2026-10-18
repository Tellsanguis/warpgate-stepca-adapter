# Configurer step-ca, les serveurs cibles et Warpgate

Ce document décrit les trois réglages qui entourent l'adaptateur. Les extraits de `ca.json` et le modèle ci-dessous sont ceux que `make integration` et `make e2e` utilisent contre un vrai step-ca 0.30.2 (voir `integration/gen/main.go` et `integration/run.sh`).

## 1. step-ca : un provisioner JWK dédié et un modèle SSH à principal fixe

L'adaptateur obtient les certificats auprès d'un provisioner **JWK** de step-ca. La sécurité repose sur le **modèle SSH** de ce provisioner : il impose le type, les principals et les extensions, quoi qu'on demande dans le jeton (test `TestCATemplateHasLastWord`).

Modèle (`<STEPPATH>/templates/ssh/warpgate-ops.tpl`) :

```
{
	"type": "user",
	"keyId": {{ toJson .KeyID }},
	"principals": ["ops"],
	"extensions": {"permit-pty": ""}
}
```

Entrée à ajouter dans `authority.provisioners` de `ca.json`, puis redémarrer step-ca :

```json
{
  "type": "JWK",
  "name": "warpgate-ops",
  "key": { "...": "clé publique JWK (kid, kty EC, crv P-256, alg ES256, use sig)" },
  "encryptedKey": "clé privée JWK chiffrée, sérialisation compacte JWE (PBES2-HS256+A128KW, A256GCM)",
  "claims": {
    "enableSSHCA": true,
    "minUserSSHCertDuration": "5m",
    "defaultUserSSHCertDuration": "5m",
    "maxUserSSHCertDuration": "10m"
  },
  "options": { "ssh": { "templateFile": "templates/ssh/warpgate-ops.tpl" } }
}
```

- Un provisioner par jeu de comptes autorisés (par exemple un pour `ops`, un autre pour un compte à droits réduits) : le principal est fixé par le modèle, donc **un rôle de l'adaptateur correspond à un provisioner**.
- L'adaptateur n'accepte que l'extension `permit-pty` : le modèle ne doit pas en émettre d'autres.
- Le fichier d'`encryptedKey` et son mot de passe sont les deux secrets que lit l'adaptateur (`key_file`, `password_file`). `integration/gen/main.go` montre une génération qui fonctionne ; l'adaptateur attend bien la forme compacte du JWE.
- Durées : voir « Durées » dans le README (minimum de 5 minutes de step-ca, Warpgate demande `5m`).

## 2. Serveurs cibles : faire confiance à la CA, un principal par compte

Sur chaque serveur SSH cible :

```
TrustedUserCAKeys /etc/ssh/ca.pub                       # clé publique de la CA SSH utilisateur de step-ca
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u    # fichier par compte, ex. "ops" contient la ligne: ops
```

Le principal du certificat doit figurer dans le fichier du compte visé. `integration/sshd/` en est un exemple minimal.

## 3. Warpgate : backend Vault et cibles à certificat

Dans Warpgate 0.30.0 : un backend de secrets de type `vault` (adresse de l'adaptateur, authentification par jeton, `allowed_paths` limité à `ssh/sign/<rôle>`), puis des cibles SSH en authentification par certificat (`backend`, `mount: ssh`, `role`). Le nom de la cible côté Warpgate fixe le compte distant (`username`) ; l'adaptateur n'autorise que les comptes de la liste blanche du rôle.

Limites de Warpgate 0.30.0 relevées pendant les tests : voir « Constats du bout en bout » dans le README (pas de CA privée pour son client Vault, pas de `Content-Type`, `WARPGATE_PEER_ADDRESS`).
