# Modèle de menaces

Portée : le service `warpgate-stepca-adapter` (Go) qui reçoit les demandes de signature de Warpgate et obtient des certificats SSH éphémères de step-ca. Hors portée : la sécurité de step-ca, de Warpgate, des cibles et de l'hôte (voir « Risques résiduels »).

## Ce qu'on protège

| Actif | Pourquoi |
|---|---|
| Clé JWK du provisioner (en mémoire) | Elle permet d'obtenir des certificats auprès de la CA, dans les limites du modèle SSH du provisioner. |
| Jetons d'API (empreintes SHA-256 en configuration) | Ils autorisent à demander des certificats. |
| Certificats émis | Ils donnent accès SSH aux cibles pendant quelques minutes. |
| Journal d'audit | Il relie un certificat à une identité (`key_id`) et à une session Warpgate. |

## Adversaires considérés

| Code | Adversaire |
|---|---|
| A1 | Attaquant réseau sans jeton (écoute, rejeu, dégradation TLS, déni de service) |
| A2 | Détenteur d'un jeton volé, ou Warpgate compromis : demandes arbitrairement forgées |
| A3 | Contenu hostile dans une requête (clé, key_id, principals, durée, JSON piégé) |
| A4 | Réponse de la CA falsifiée ou piégée (homme du milieu, CA compromise partiellement) |
| A5 | Lecteur des journaux ou des erreurs (fuite de secrets) |
| A6 | Compte local non privilégié sur l'hôte (fichiers de configuration et de clés) |

## Menaces, contrôles, preuves

| Menace | Contrôle | Test |
|---|---|---|
| A1 Écoute ou dégradation TLS | TLS 1.3 obligatoire, pas de HTTP en clair, HTTP/2 désactivé | `TestRunEndToEnd`, `TestAdapterRequiresTLS13` |
| A1 Jeton deviné ou comparé par temps de réponse | Comparaison des empreintes SHA-256 en temps constant, sur tous les jetons sans sortie anticipée | `TestMultipleTokensAllCompared`, `TestAuthDenied` |
| A1 Oracle de jeton ou de rôle | Réponse identique (403) pour jeton absent, faux, rôle inconnu ou interdit | `TestAuthDenied` |
| A1 Force brute, inondation | Limite d'échecs (429), quota de signatures **par jeton** et par minute, tailles et délais bornés | `TestRateLimits`, `TestSignRejections` |
| A1 Certificat TLS expiré après renouvellement | Relecture des fichiers à chaque changement, l'ancien certificat reste servi si le nouveau est invalide | `TestCertReloader` |
| Exploitation: conteneur « unhealthy » à tort | La sonde de santé vise l'adresse d'écoute réelle | `TestHealthURL` |
| A2 Principal interdit (root, autre compte) | Liste blanche de principals par rôle, `root` refusé en dur, un seul principal | `TestParseSignRequestRejects`, `FuzzParseSignRequest`, `TestConfigRejects` |
| A2 Jeton utilisable sur tous les rôles | Chaque jeton liste ses rôles | `TestAuthDenied` |
| A2 Identité usurpée dans `key_id` | Préfixe `warpgate:` obligatoire, caractères imprimables, 256 octets max | `TestParseSignRequestRejects`, `FuzzParseSignRequest` |
| A2 Clé ou durée dangereuse | Ed25519 seulement, pas de certificat ni d'options, TTL borné par rôle (1 h en dur) | `TestParseSignRequestRejects`, `TestConfigRejects` |
| A2 Adaptateur compromis demandant root à la CA | Le modèle SSH du provisioner fixe les principals côté CA | `TestCATemplateHasLastWord` (CA réelle) |
| A3 JSON ambigu, champs inconnus, données après l'objet | Décodage strict, `DisallowUnknownFields`, rejet des données en trop | `TestParseSignRequestRejects`, `FuzzParseSignRequest` |
| A4 Certificat de la CA différent de la demande | Vérification complète : type, clé, key id, principals, expiration, `force-command`, signature | `TestSignRejectsBadCertificates` |
| A4 Certificat signé par une autre autorité | La clé CA est lue en TLS au démarrage et comparée explicitement | `TestSignRejectsBadCertificates` (cas « signé par une autre CA ») |
| A4 Serveur CA usurpé | Racine de la CA épinglée, pas de proxy implicite, pas de redirection suivie | `TestNewCAClientStartup`, `TestSignCAFailures` |
| A4 Réponse énorme ou lente | Taille bornée à 64 Kio, délais et annulation par contexte | `TestSignCAFailures`, `TestSignHonorsContext` |
| A4 Rejeu du jeton JWK | Jeton de 30 s, `jti` aléatoire, refus de la CA | `TestSignHappyPathAndTokenClaims`, `TestCARejectsReplayAndForeignKeys` |
| A5 Secret dans les journaux ou erreurs | Journal sans en-tête, jeton ni clé publique complète ; erreurs génériques vers le client ; corps de la CA jamais reporté | `TestJournalNeverContainsSecrets`, `TestSignUpstreamFailureIsGeneric`, `TestSignCAFailures`, `TestPanicIsContained` |
| A6 Fichiers lisibles par d'autres comptes | Clé TLS, JWK chiffré et mot de passe refusés au-delà de 0600, JWK chiffré au repos | `TestConfigRejects`, `TestRunFailsClosed` |
| Toutes : configuration permissive par erreur | Refus au démarrage (fail closed) pour toute valeur invalide (port de `listen` compris), donnée après l'objet JSON, CA injoignable ou clé inutilisable | `TestConfigRejects`, `TestLoadConfigStrictJSON`, `TestLoadConfigTrailingData`, `TestRunFailsClosed`, `TestLoadRoleSigner` |
| Chaîne d'approvisionnement | Images épinglées par digest, dépendances minimales, `govulncheck`, `gosec`, `staticcheck`, `hadolint`, `trivy` dans `make security` | `make security` |
| Conteneur | Image sans shell, utilisateur non root, lecture seule, sans capacités, `no-new-privileges` | `integration/run.sh` (lancement durci), `make hadolint`, `make scan` |

## Risques résiduels (acceptés ou à traiter ailleurs)

1. **Jeton volé** : il permet d'obtenir des certificats pour les principals de ses rôles tant qu'il n'est pas révoqué. Mitigations : rotation, filtrage IP sur le port de l'adaptateur (nftables et FortiGate), certificats de 5 minutes, journal d'audit. Pas de TLS mutuel (YAGNI à ce stade).
2. **Compromission de l'hôte** : l'attaquant lit la clé JWK en mémoire (ou le fichier et son mot de passe). Le dommage est borné par le modèle SSH du provisioner (principals et durée) mais pas nul. Hébergement recommandé : sur la VM de la CA.
3. **Pas de révocation** : aucun KRL ; la durée de vie courte (5 min) en tient lieu.
4. **Rotation de la CA SSH** : les clés de la CA sont lues une fois au démarrage et épinglées. Après rotation, tout certificat est refusé (échec fermé, 502) jusqu'au redémarrage de l'adaptateur. C'est un choix assumé : une rotation impose de toute façon de mettre à jour `TrustedUserCAKeys` partout ; « redémarrer l'adaptateur » fait partie de la procédure (voir README).
5. **Certificat TLS de l'adaptateur** : relu automatiquement quand les fichiers changent (Let's Encrypt). Reste à surveiller : la date d'expiration (alerte de supervision) et les droits du fichier de clé écrit par le client ACME.
6. **Limiteurs en mémoire** : fenêtre fixe d'une minute, remis à zéro au redémarrage. Le quota de signatures est par jeton ; le limiteur d'échecs d'authentification est global (30 par minute) : après 30 échecs, les refus répondent 429, jamais une requête valide. Seul Warpgate doit pouvoir joindre le port, donc ces échecs ne peuvent venir que de lui si le filtrage IP est correct. Un attaquant qui détient un jeton valide peut épuiser le quota de ce jeton (déni de service ciblé, sans élévation).
7. **Vulnérabilité signalée par `govulncheck`** : GO-2026-5932 (`golang.org/x/crypto/openpgp`, sans correctif). Le paquet n'est pas importé et n'est pas appelé ; à revérifier à chaque mise à jour.
8. **Le journal part sur la sortie standard** : son intégrité dépend du collecteur (journald puis Graylog).
9. **Falsification d'attribution par un jeton volé** : un détenteur du jeton peut choisir n'importe quel nom dans `warpgate:<nom>:<session>` (le préfixe est contrôlé, pas le reste). L'attribution des certificats n'est fiable que tant que le jeton l'est.
10. **Connexions simultanées non limitées** et journal de refus non échantillonné : un inondeur réseau peut faire grossir le journal ; le filtrage IP en amont (nftables, FortiGate) est la parade.
11. **Le trajet Warpgate vers l'adaptateur** : Warpgate 0.30.0 ne vérifie que les racines publiques. Avec un certificat **Let's Encrypt** sur un nom public, la vérification TLS fonctionne (`tls_skip_verify` à faux) et ce risque disparaît. Avec un certificat de CA privée, il faudrait `tls_skip_verify` : homme du milieu possible sur ce segment, à compenser par filtrage IP strict, rotation courte du jeton et vérification des certificats par Warpgate lui-même.
12. **Clés JSON dupliquées** : la dernière valeur l'emporte (`encoding/json`). Sans effet exploitable : l'adaptateur valide et signe la même valeur finale, et l'accès d'un utilisateur est fixé par ses rôles Warpgate. Un attaquant sans jeton n'atteint pas ce code ; avec un jeton, il obtient au mieux les principals déjà autorisés pour ce jeton.
13. **Un client unique** : Ed25519 et préfixe `warpgate:` sont des choix fixés dans le code (`shortcut:` commentés).

## Revue

| Date | Quoi | Résultat |
|---|---|---|
| 2026-10-20 | Tests unitaires (course), fuzzing, `govulncheck`, `staticcheck`, `gosec`, `hadolint`, `trivy`, intégration contre step-ca 0.30.2, bout en bout avec Warpgate 0.30.0 et un sshd cible | Tous passent (`make security`, `make e2e`) |
| à faire | Passe Strix (clé de modèle requise) | `make strix` |
| à faire | Revue de sécurité complémentaire avant une première mise en production | |
