# Politique de sécurité / Security policy

Ce service signe des certificats SSH : un défaut de sécurité peut ouvrir l'accès à des serveurs. Merci de le signaler en privé avant toute publication.

*This service issues SSH certificates: a security flaw can grant access to servers. Please report it privately before any public disclosure.*

- **Contact** : mael.bene@tellserv.fr (objet « SECURITY warpgate-stepca-adapter »). Ne pas ouvrir de ticket public pour une faille.
- **Versions concernées** : la dernière version publiée.
- **Délai** : accusé de réception sous 7 jours, correctif ou plan sous 30 jours selon la gravité. Projet maintenu à titre personnel, sans garantie de délai.
- **Périmètre** : le code de ce dépôt. Les limites connues (jeton volé, absence de révocation, trajet Warpgate vers l'adaptateur) sont décrites dans `security/threat-model.md` ; les signaler comme faille n'est pas nécessaire.
- **Ce qui aide** : version, configuration (sans secret), journal d'audit de l'adaptateur et, si possible, un test qui reproduit le problème.
