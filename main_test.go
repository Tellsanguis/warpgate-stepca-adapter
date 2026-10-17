package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// selfSigned écrit un certificat auto-signé pour 127.0.0.1 (clé en 0600) et rend son PEM.
func selfSigned(t *testing.T, dir string) (certPath, keyPath string, pool *x509.CertPool) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "adapter-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(k)
	certPath, keyPath = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	_ = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	pool = x509.NewCertPool()
	c, _ := x509.ParseCertificate(der)
	pool.AddCert(c)
	return
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func TestRunEndToEnd(t *testing.T) {
	h := newHarness(t) // fausse CA + rôle de test
	dir := t.TempDir()
	cert, key, pool := selfSigned(t, dir)
	addr := freePort(t)
	cfg := Config{
		Listen: addr, TLSCert: cert, TLSKey: key, Mount: "ssh",
		CA:     CAConfig{URL: h.ca.srv.URL, RootFile: h.ca.root(t)},
		Roles:  map[string]RoleConfig{"ops": h.ca.prov.role},
		Tokens: []TokenConfig{{Name: "warpgate", SHA256: hashOf(tokOps), Roles: []string{"ops"}}},
	}
	cfg.Roles["ops"] = RoleConfig{Provisioner: provName, KeyFile: h.ca.prov.role.KeyFile, PasswordFile: h.ca.prov.role.PasswordFile,
		Principals: []string{"ops"}, MaxTTL: "10m"}
	raw, _ := json.Marshal(cfg)
	cfgPath := filepath.Join(dir, "config.json")
	_ = os.WriteFile(cfgPath, raw, 0o600)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath, slog.New(slog.NewJSONHandler(io.Discard, nil))) }()

	client := func(max uint16) *http.Client {
		return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MaxVersion: max}}}
	}
	var resp *http.Response
	var err error
	for i := 0; i < 50; i++ { // attend le démarrage
		req, _ := http.NewRequest("GET", "https://"+addr+"/v1/auth/token/lookup-self", nil)
		req.Header.Set("X-Vault-Token", tokOps)
		if resp, err = client(tls.VersionTLS13).Do(req); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("service injoignable: %v", err)
	}
	resp.Body.Close()

	h2 := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: pool}}}
	if r, err := h2.Get("https://" + addr + "/healthz"); err != nil || r.ProtoMajor != 1 {
		t.Errorf("HTTP/2 négocié ou service injoignable (err=%v)", err)
	}
	if _, err := client(tls.VersionTLS12).Get("https://" + addr + "/healthz"); err == nil {
		t.Error("TLS 1.2 accepté: le service doit exiger TLS 1.3")
	}
	if r, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + addr + "/healthz"); err == nil {
		b, _ := io.ReadAll(r.Body)
		if r.StatusCode == 200 && bytes.Contains(b, []byte("ok")) {
			t.Error("HTTP en clair accepté")
		}
	}
	if err := healthcheck(cfgPath); err != nil {
		t.Errorf("healthcheck: %v", err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("arrêt: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("l'arrêt est trop long")
	}
	if err := healthcheck(cfgPath); err == nil {
		t.Error("healthcheck réussit alors que le service est arrêté")
	}
}

// Au démarrage, tout défaut est fatal: configuration, CA injoignable ou clé de provisioner inutilisable.
func TestRunFailsClosed(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	cert, key, _ := selfSigned(t, dir)
	base := func() Config {
		return Config{
			Listen: "127.0.0.1:0", TLSCert: cert, TLSKey: key, Mount: "ssh",
			CA: CAConfig{URL: h.ca.srv.URL, RootFile: h.ca.root(t)},
			Roles: map[string]RoleConfig{"ops": {Provisioner: provName, KeyFile: h.ca.prov.role.KeyFile,
				PasswordFile: h.ca.prov.role.PasswordFile, Principals: []string{"ops"}, MaxTTL: "10m"}},
			Tokens: []TokenConfig{{Name: "warpgate", SHA256: hashOf(tokOps), Roles: []string{"ops"}}},
		}
	}
	cases := map[string]func(c *Config){
		"CA injoignable": func(c *Config) { c.CA.URL = "https://127.0.0.1:1" },
		"mot de passe JWK faux": func(c *Config) {
			r := c.Roles["ops"]
			r.PasswordFile = writeFile(t, "pw", "faux", 0o600)
			c.Roles["ops"] = r
		},
		"clé TLS lisible par tous": func(c *Config) { _ = os.Chmod(c.TLSKey, 0o644) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := base()
			mutate(&c)
			raw, _ := json.Marshal(c)
			p := filepath.Join(t.TempDir(), "c.json")
			_ = os.WriteFile(p, raw, 0o600)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err := run(ctx, p, slog.New(slog.NewJSONHandler(io.Discard, nil)))
			if err == nil || strings.Contains(err.Error(), "faux") { // le mauvais mot de passe ne doit pas fuiter dans l'erreur
				t.Fatalf("démarrage aurait dû échouer proprement: %v", err)
			}
		})
	}
}

func TestHealthURL(t *testing.T) {
	for listen, want := range map[string]string{
		":8200":          "https://127.0.0.1:8200/healthz",
		"0.0.0.0:8200":   "https://127.0.0.1:8200/healthz",
		"[::]:8200":      "https://127.0.0.1:8200/healthz",
		"10.0.0.5:8200":  "https://10.0.0.5:8200/healthz", // écoute sur une IP précise: la boucle locale ne répondrait pas
		"[fd00::5]:8200": "https://[fd00::5]:8200/healthz",
		"127.0.0.1:8200": "https://127.0.0.1:8200/healthz",
	} {
		got, err := healthURL(listen)
		if err != nil || got != want {
			t.Errorf("healthURL(%q) = %q, %v; attendu %q", listen, got, err, want)
		}
	}
	if _, err := healthURL("pas-un-hote-port"); err == nil {
		t.Error("une adresse sans port doit échouer")
	}
}

// writeCert écrit une paire certificat/clé de numéro de série donné et force une date de modification distincte.
func writeCert(t *testing.T, dir string, serial int64, mod time.Time) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "reload"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"adapter"}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(k)
	for name, data := range map[string][]byte{
		"tls.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		"tls.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
}

func serialOf(t *testing.T, c *tls.Certificate) int64 {
	t.Helper()
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.SerialNumber.Int64()
}

// Renouvellement (Let's Encrypt): le nouveau certificat est servi sans redémarrage; un fichier cassé ne remplace jamais le bon.
func TestCertReloader(t *testing.T) {
	dir := t.TempDir()
	logs := &bytes.Buffer{}
	base := time.Now().Add(-time.Hour)
	writeCert(t, dir, 1, base)
	r, err := newCertReloader(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), slog.New(slog.NewJSONHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	cur := func() int64 {
		c, err := r.get(nil)
		if err != nil {
			t.Fatal(err)
		}
		return serialOf(t, c)
	}
	if got := cur(); got != 1 {
		t.Fatalf("serial %d, attendu 1", got)
	}
	writeCert(t, dir, 2, base.Add(time.Minute))
	if got := cur(); got != 2 {
		t.Fatalf("après renouvellement: serial %d, attendu 2", got)
	}
	// Fichier corrompu: l'ancien certificat reste servi, l'erreur est journalisée une seule fois.
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), []byte("corrompu"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(filepath.Join(dir, "tls.crt"), base.Add(2*time.Minute), base.Add(2*time.Minute))
	for i := 0; i < 3; i++ {
		if got := cur(); got != 2 {
			t.Fatalf("fichier corrompu: serial %d, attendu 2 (ancien certificat)", got)
		}
	}
	if n := strings.Count(logs.String(), "tls_reload_failed"); n != 1 {
		t.Fatalf("erreur journalisée %d fois, attendu 1", n)
	}
	writeCert(t, dir, 3, base.Add(3*time.Minute))
	if got := cur(); got != 3 {
		t.Fatalf("après réparation: serial %d, attendu 3", got)
	}
	// Démarrage avec un certificat invalide: échec (pas de service sans certificat).
	bad := t.TempDir()
	_ = os.WriteFile(filepath.Join(bad, "tls.crt"), []byte("x"), 0o600)
	_ = os.WriteFile(filepath.Join(bad, "tls.key"), []byte("x"), 0o600)
	if _, err := newCertReloader(filepath.Join(bad, "tls.crt"), filepath.Join(bad, "tls.key"), slog.New(slog.NewJSONHandler(io.Discard, nil))); err == nil {
		t.Fatal("démarrage possible avec un certificat invalide")
	}
}
