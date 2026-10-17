package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

const (
	maxKeyIDLen = 256
	// Warpgate fabrique toujours `warpgate:<utilisateur>:<session>` (certificate.rs). Exiger ce préfixe empêche un
	// jeton volé de fabriquer un certificat dont l'identité imite un autre système.
	// shortcut: préfixe fixe dans le code, à passer en configuration si un second client apparaît.
	keyIDPrefix = "warpgate:"
	defaultTTL  = 5 * time.Minute
)

// reqError porte un code court pour le journal d'audit; le client ne reçoit jamais le détail.
type reqError string

func (e reqError) Error() string { return string(e) }

// signRequest reprend les champs que Warpgate envoie (vaultrs SignSSHKeyRequest).
// critical_options et extensions sont acceptés seulement vides: l'adaptateur ne les transmet jamais.
type signRequest struct {
	PublicKey       string          `json:"public_key"`
	CertType        string          `json:"cert_type"`
	ValidPrincipals string          `json:"valid_principals"`
	KeyID           string          `json:"key_id"`
	TTL             string          `json:"ttl"`
	CriticalOptions json.RawMessage `json:"critical_options"`
	Extensions      json.RawMessage `json:"extensions"`
}

type validated struct {
	Key       ssh.PublicKey
	Principal string
	KeyID     string
	TTL       time.Duration
}

// parseSignRequest valide tout ce qui vient du client. Tout ce qui n'est pas explicitement accepté est refusé.
func parseSignRequest(body io.Reader, role RoleConfig) (*validated, error) {
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	var r signRequest
	if err := dec.Decode(&r); err != nil {
		return nil, reqError("json_invalide")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, reqError("donnees_apres_json")
	}
	for _, raw := range []json.RawMessage{r.CriticalOptions, r.Extensions} {
		if s := strings.TrimSpace(string(raw)); s != "" && s != "null" && s != "{}" {
			return nil, reqError("option_non_supportee")
		}
	}
	if r.CertType != "" && r.CertType != "user" {
		return nil, reqError("cert_type")
	}

	key, err := parseKey(r.PublicKey)
	if err != nil {
		return nil, err
	}
	if r.ValidPrincipals == "" || strings.Contains(r.ValidPrincipals, ",") || !slices.Contains(role.Principals, r.ValidPrincipals) {
		return nil, reqError("principal_interdit")
	}
	if !validKeyID(r.KeyID) {
		return nil, reqError("key_id")
	}
	ttl, err := parseTTL(r.TTL, role.maxTTL)
	if err != nil {
		return nil, err
	}
	return &validated{Key: key, Principal: r.ValidPrincipals, KeyID: r.KeyID, TTL: ttl}, nil
}

// parseKey n'accepte qu'une seule clé publique ssh-ed25519 (le seul type que Warpgate génère), sans options ni certificat.
// shortcut: Ed25519 seulement, ajouter ecdsa/rsa si un autre client est branché.
func parseKey(s string) (ssh.PublicKey, error) {
	if len(s) == 0 || len(s) > 1024 {
		return nil, reqError("cle_taille")
	}
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(s))
	if err != nil || len(options) > 0 || len(bytes.TrimSpace(rest)) > 0 {
		return nil, reqError("cle_illisible")
	}
	if key.Type() != ssh.KeyAlgoED25519 {
		return nil, reqError("cle_type")
	}
	return key, nil
}

func validKeyID(s string) bool {
	if len(s) > maxKeyIDLen || !strings.HasPrefix(s, keyIDPrefix) || len(s) == len(keyIDPrefix) {
		return false
	}
	// RuneError couvre aussi l'UTF-8 invalide: le décodeur JSON le remplace par U+FFFD avant d'arriver ici.
	for _, c := range s {
		if !unicode.IsPrint(c) || c == utf8.RuneError {
			return false
		}
	}
	return true
}

func parseTTL(s string, max time.Duration) (time.Duration, error) {
	if s == "" {
		return min(defaultTTL, max), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 || d > max {
		return 0, reqError("ttl")
	}
	return d, nil
}
