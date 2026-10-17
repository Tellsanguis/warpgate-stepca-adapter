package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

var testRole = RoleConfig{Principals: []string{"ops", "deploy"}, maxTTL: 10 * time.Minute}

func authorized(t testing.TB, pub any) string {
	t.Helper()
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

func edKey(t testing.TB) string {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	return authorized(t, pub)
}

// body construit un corps de requête valide, modifiable champ par champ.
func body(t testing.TB, mutate func(m map[string]any)) string {
	t.Helper()
	m := map[string]any{
		"public_key": edKey(t), "cert_type": "user", "valid_principals": "ops",
		"key_id": "warpgate:alice:7f3c", "ttl": "5m",
	}
	if mutate != nil {
		mutate(m)
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func TestParseSignRequestValid(t *testing.T) {
	v, err := parseSignRequest(strings.NewReader(body(t, nil)), testRole)
	if err != nil {
		t.Fatal(err)
	}
	if v.Principal != "ops" || v.KeyID != "warpgate:alice:7f3c" || v.TTL != 5*time.Minute || v.Key.Type() != ssh.KeyAlgoED25519 {
		t.Fatalf("résultat inattendu: %+v", v)
	}
}

// Ce que Warpgate envoie réellement peut contenir des champs optionnels à null.
func TestParseSignRequestAcceptsNullOptionals(t *testing.T) {
	b := body(t, func(m map[string]any) { m["critical_options"] = nil; m["extensions"] = nil })
	if _, err := parseSignRequest(strings.NewReader(b), testRole); err != nil {
		t.Fatal(err)
	}
	b = body(t, func(m map[string]any) { m["extensions"] = map[string]string{} })
	if _, err := parseSignRequest(strings.NewReader(b), testRole); err != nil {
		t.Fatal(err)
	}
}

func TestParseSignRequestDefaults(t *testing.T) {
	b := body(t, func(m map[string]any) { delete(m, "ttl"); delete(m, "cert_type") })
	v, err := parseSignRequest(strings.NewReader(b), testRole)
	if err != nil || v.TTL != 5*time.Minute {
		t.Fatalf("ttl par défaut: %v %v", v, err)
	}
	short := RoleConfig{Principals: []string{"ops"}, maxTTL: time.Minute}
	if v, err = parseSignRequest(strings.NewReader(b), short); err != nil || v.TTL != time.Minute {
		t.Fatalf("ttl par défaut plafonné: %v %v", v, err)
	}
}

func TestParseSignRequestRejects(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caSigner, _ := ssh.NewSignerFromKey(caPriv)
	userPub, _, _ := ed25519.GenerateKey(rand.Reader)
	userKey, _ := ssh.NewPublicKey(userPub)
	cert := &ssh.Certificate{Key: userKey, CertType: ssh.UserCert, ValidPrincipals: []string{"root"}, ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}
	two := edKey(t) + "\n" + edKey(t)

	cases := map[string]struct {
		mutate func(m map[string]any)
		code   reqError
	}{
		"clé RSA":                   {func(m map[string]any) { m["public_key"] = authorized(t, &rsaKey.PublicKey) }, "cle_type"},
		"clé ECDSA":                 {func(m map[string]any) { m["public_key"] = authorized(t, &ecKey.PublicKey) }, "cle_type"},
		"certificat à la place":     {func(m map[string]any) { m["public_key"] = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert))) }, "cle_type"},
		"deux clés":                 {func(m map[string]any) { m["public_key"] = two }, "cle_illisible"},
		"options devant la clé":     {func(m map[string]any) { m["public_key"] = `command="id" ` + edKey(t) }, "cle_illisible"},
		"clé illisible":             {func(m map[string]any) { m["public_key"] = "ssh-ed25519 AAAA" }, "cle_illisible"},
		"clé vide":                  {func(m map[string]any) { m["public_key"] = "" }, "cle_taille"},
		"clé énorme":                {func(m map[string]any) { m["public_key"] = strings.Repeat("A", 5000) }, "cle_taille"},
		"cert_type host":            {func(m map[string]any) { m["cert_type"] = "host" }, "cert_type"},
		"principal absent":          {func(m map[string]any) { m["valid_principals"] = "" }, "principal_interdit"},
		"principal hors liste":      {func(m map[string]any) { m["valid_principals"] = "postgres" }, "principal_interdit"},
		"principal root":            {func(m map[string]any) { m["valid_principals"] = "root" }, "principal_interdit"},
		"deux principals":           {func(m map[string]any) { m["valid_principals"] = "ops,deploy" }, "principal_interdit"},
		"principal avec espace":     {func(m map[string]any) { m["valid_principals"] = "ops " }, "principal_interdit"},
		"principal majuscule":       {func(m map[string]any) { m["valid_principals"] = "OPS" }, "principal_interdit"},
		"key_id vide":               {func(m map[string]any) { m["key_id"] = "" }, "key_id"},
		"key_id sans préfixe":       {func(m map[string]any) { m["key_id"] = "alice@example.org" }, "key_id"},
		"key_id préfixe seul":       {func(m map[string]any) { m["key_id"] = "warpgate:" }, "key_id"},
		"key_id trop long":          {func(m map[string]any) { m["key_id"] = "warpgate:" + strings.Repeat("a", 300) }, "key_id"},
		"key_id retour ligne":       {func(m map[string]any) { m["key_id"] = "warpgate:a\nb" }, "key_id"},
		"key_id caractère nul":      {func(m map[string]any) { m["key_id"] = "warpgate:a\x00b" }, "key_id"},
		"key_id espace insécable 0": {func(m map[string]any) { m["key_id"] = "warpgate:a\u200bb" }, "key_id"},
		"key_id UTF-8 invalide":     {func(m map[string]any) { m["key_id"] = "warpgate:\xff\xfe" }, "key_id"},
		"ttl négatif":               {func(m map[string]any) { m["ttl"] = "-5m" }, "ttl"},
		"ttl nul":                   {func(m map[string]any) { m["ttl"] = "0s" }, "ttl"},
		"ttl trop long":             {func(m map[string]any) { m["ttl"] = "11m" }, "ttl"},
		"ttl illisible":             {func(m map[string]any) { m["ttl"] = "5 minutes" }, "ttl"},
		"ttl en secondes nues":      {func(m map[string]any) { m["ttl"] = "300" }, "ttl"},
		"extensions non vides":      {func(m map[string]any) { m["extensions"] = map[string]string{"permit-port-forwarding": ""} }, "option_non_supportee"},
		"options critiques":         {func(m map[string]any) { m["critical_options"] = map[string]string{"force-command": "x"} }, "option_non_supportee"},
		"champ inconnu":             {func(m map[string]any) { m["role"] = "admin" }, "json_invalide"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseSignRequest(strings.NewReader(body(t, c.mutate)), testRole)
			if err == nil {
				t.Fatal("aurait dû être refusé")
			}
			if err != c.code {
				t.Fatalf("code = %v, attendu %v", err, c.code)
			}
		})
	}
	for name, raw := range map[string]string{
		"pas du JSON":     `ceci n'est pas du json`,
		"tableau":         `[]`,
		"données en trop": body(t, nil) + `{"a":1}`,
		"corps vide":      ``,
	} {
		if _, err := parseSignRequest(strings.NewReader(raw), testRole); err == nil {
			t.Errorf("%s: aurait dû être refusé", name)
		}
	}
}

// Invariants de sécurité tenus pour toute entrée: si la requête passe, elle respecte les politiques.
func FuzzParseSignRequest(f *testing.F) {
	f.Add(body(f, nil))
	f.Add(`{"public_key":"x","valid_principals":"ops,root","key_id":"warpgate:\u0000","ttl":"99h"}`)
	f.Add(`{"extensions":{"a":"b"}}`)
	f.Fuzz(func(t *testing.T, raw string) {
		v, err := parseSignRequest(strings.NewReader(raw), testRole)
		if err != nil {
			return
		}
		if v.Key.Type() != ssh.KeyAlgoED25519 {
			t.Fatalf("type de clé %s accepté", v.Key.Type())
		}
		if v.Principal != "ops" && v.Principal != "deploy" {
			t.Fatalf("principal %q accepté", v.Principal)
		}
		if !strings.HasPrefix(v.KeyID, keyIDPrefix) || len(v.KeyID) > maxKeyIDLen || strings.ContainsAny(v.KeyID, "\x00\r\n") {
			t.Fatalf("key_id %q accepté", v.KeyID)
		}
		if v.TTL <= 0 || v.TTL > testRole.maxTTL {
			t.Fatalf("ttl %v accepté", v.TTL)
		}
	})
}
