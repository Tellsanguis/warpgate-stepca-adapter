package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const hashA = "0000000000000000000000000000000000000000000000000000000000000001"
const hashB = "0000000000000000000000000000000000000000000000000000000000000002"

// testConfig écrit des fichiers secrets 0600 et retourne une configuration valide.
func testConfig(t *testing.T) *Config {
	t.Helper()
	d := t.TempDir()
	w := func(name string, mode os.FileMode) string {
		p := filepath.Join(d, name)
		if err := os.WriteFile(p, []byte("x"), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	return &Config{
		Listen:  "127.0.0.1:8200",
		TLSCert: w("cert.pem", 0o644),
		TLSKey:  w("key.pem", 0o600),
		Mount:   "ssh",
		CA:      CAConfig{URL: "https://ca.example:8443", RootFile: w("root.crt", 0o644)},
		Roles: map[string]RoleConfig{"ops": {
			Provisioner: "warpgate-ops", KeyFile: w("jwk.json", 0o600), PasswordFile: w("pw", 0o400),
			Principals: []string{"ops"}, MaxTTL: "10m",
		}},
		Tokens: []TokenConfig{{Name: "warpgate", SHA256: hashA, Roles: []string{"ops"}}},
	}
}

func TestConfigValid(t *testing.T) {
	c := testConfig(t)
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	if c.RatePerMinute != 60 || c.Roles["ops"].maxTTL.Minutes() != 10 {
		t.Fatalf("valeurs par défaut/analysées incorrectes: %+v", c)
	}
}

// Chaque mutation doit être refusée: la configuration échoue fermée.
func TestConfigRejects(t *testing.T) {
	cases := map[string]func(c *Config){
		"listen sans port":          func(c *Config) { c.Listen = "localhost" },
		"listen port non numérique": func(c *Config) { c.Listen = ":abc" },
		"listen port trop grand":    func(c *Config) { c.Listen = "10.0.0.5:99999" },
		"listen port nul":           func(c *Config) { c.Listen = "127.0.0.1:0" },
		"sans TLS":                  func(c *Config) { c.TLSCert = "" },
		"clé TLS lisible":           func(c *Config) { _ = os.Chmod(c.TLSKey, 0o644) },
		"mount avec slash":          func(c *Config) { c.Mount = "ssh/../sys" },
		"rate hors bornes":          func(c *Config) { c.RatePerMinute = 100000 },
		"CA en http":                func(c *Config) { c.CA.URL = "http://ca.example:8443" },
		"CA avec chemin":            func(c *Config) { c.CA.URL = "https://ca.example/x" },
		"CA avec identifiants":      func(c *Config) { c.CA.URL = "https://u:p@ca.example" },
		"CA sans racine":            func(c *Config) { c.CA.RootFile = "" },
		"aucun jeton":               func(c *Config) { c.Tokens = nil },
		"jeton hash court":          func(c *Config) { c.Tokens[0].SHA256 = "abc" },
		"jeton hash majuscules":     func(c *Config) { c.Tokens[0].SHA256 = strings.Repeat("A", 64) },
		"jeton sans rôle":           func(c *Config) { c.Tokens[0].Roles = nil },
		"jeton rôle inconnu":        func(c *Config) { c.Tokens[0].Roles = []string{"admin"} },
		"jetons hash en double": func(c *Config) {
			c.Tokens = append(c.Tokens, TokenConfig{Name: "b", SHA256: hashA, Roles: []string{"ops"}})
		},
		"jetons nom en double": func(c *Config) {
			c.Tokens = append(c.Tokens, TokenConfig{Name: "warpgate", SHA256: hashB, Roles: []string{"ops"}})
		},
		"principal root":          func(c *Config) { r := c.Roles["ops"]; r.Principals = []string{"root"}; c.Roles["ops"] = r },
		"principal avec virgule":  func(c *Config) { r := c.Roles["ops"]; r.Principals = []string{"ops,root"}; c.Roles["ops"] = r },
		"principal majuscule":     func(c *Config) { r := c.Roles["ops"]; r.Principals = []string{"Ops"}; c.Roles["ops"] = r },
		"principal en double":     func(c *Config) { r := c.Roles["ops"]; r.Principals = []string{"ops", "ops"}; c.Roles["ops"] = r },
		"aucun principal":         func(c *Config) { r := c.Roles["ops"]; r.Principals = nil; c.Roles["ops"] = r },
		"ttl trop long":           func(c *Config) { r := c.Roles["ops"]; r.MaxTTL = "24h"; c.Roles["ops"] = r },
		"ttl nul":                 func(c *Config) { r := c.Roles["ops"]; r.MaxTTL = "0s"; c.Roles["ops"] = r },
		"ttl illisible":           func(c *Config) { r := c.Roles["ops"]; r.MaxTTL = "bientot"; c.Roles["ops"] = r },
		"provisioner invalide":    func(c *Config) { r := c.Roles["ops"]; r.Provisioner = "a/b"; c.Roles["ops"] = r },
		"mot de passe lisible":    func(c *Config) { _ = os.Chmod(c.Roles["ops"].PasswordFile, 0o644) },
		"clé JWK absente":         func(c *Config) { r := c.Roles["ops"]; r.KeyFile = "/nulle/part"; c.Roles["ops"] = r },
		"nom de rôle avec espace": func(c *Config) { c.Roles["a b"] = c.Roles["ops"] },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := testConfig(t)
			mutate(c)
			if err := c.validate(); err == nil {
				t.Fatal("la configuration aurait dû être refusée")
			}
		})
	}
}

func TestLoadConfigStrictJSON(t *testing.T) {
	d := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(d, "c.json")
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for name, body := range map[string]string{
		"champ inconnu":   `{"listen":"127.0.0.1:1","insecure":true}`,
		"JSON invalide":   `{`,
		"données en trop": `{} {}`,
		"vide":            ``,
	} {
		if _, err := loadConfig(write(body)); err == nil {
			t.Errorf("%s: aurait dû échouer", name)
		}
	}
	if _, err := loadConfig(filepath.Join(d, "absent.json")); err == nil {
		t.Error("fichier absent: aurait dû échouer")
	}
}

// Un `}` ou un `]` en trop après l'objet échappe à Decoder.More(): seul EOF prouve qu'il ne reste rien.
func TestLoadConfigTrailingData(t *testing.T) {
	raw, err := json.Marshal(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	write := func(extra string) string {
		p := filepath.Join(t.TempDir(), "c.json")
		if err := os.WriteFile(p, append(append([]byte{}, raw...), extra...), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := loadConfig(write("\n")); err != nil {
		t.Fatalf("configuration valide refusée: %v", err)
	}
	for _, extra := range []string{"}", "]", " }", "x", `{"a":1}`} {
		if _, err := loadConfig(write(extra)); err == nil {
			t.Errorf("données %q après l'objet acceptées", extra)
		}
	}
}
