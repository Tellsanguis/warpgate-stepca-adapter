package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/crypto/ssh"
)

const provName = "warpgate-ops"
const provPassword = "mot de passe de test"

// provKey: clé de provisioner de test (ES256) et ses fichiers chiffrés, comme dans ca.json.
type provKey struct {
	priv      *ecdsa.PrivateKey
	kid       string
	role      RoleConfig
	jwkPlain  []byte
	encrypted string
}

func encryptJWK(t testing.TB, plain []byte, pw string) string {
	t.Helper()
	enc, err := jose.NewEncrypter(jose.A256GCM,
		jose.Recipient{Algorithm: jose.PBES2_HS256_A128KW, Key: []byte(pw), PBES2Count: 1000}, nil)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := enc.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	s, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func writeFile(t testing.TB, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func newProvKey(t testing.TB) *provKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.JSONWebKey{Key: priv, KeyID: "kid-test", Algorithm: "ES256", Use: "sig"}
	plain, _ := json.Marshal(jwk)
	p := &provKey{priv: priv, kid: jwk.KeyID, jwkPlain: plain, encrypted: encryptJWK(t, plain, provPassword)}
	p.role = RoleConfig{
		Provisioner: provName, Principals: []string{"ops"}, maxTTL: 10 * time.Minute,
		KeyFile:      writeFile(t, "jwk.jwe", p.encrypted, 0o600),
		PasswordFile: writeFile(t, "pw", provPassword+"\n", 0o600),
	}
	return p
}

// fakeCA imite l'API de step-ca: vérifie le jeton comme le ferait un provisioner JWK, refuse les rejeux, signe un vrai certificat.
type fakeCA struct {
	t       *testing.T
	srv     *httptest.Server
	prov    *provKey
	caKey   ed25519.PrivateKey
	caPub   ssh.PublicKey
	mu      sync.Mutex
	jtis    map[string]bool
	headers []jose.Header
	claims  []jwt.Claims
	steps   []map[string]any
	bodies  []map[string]any

	before func(c *ssh.Certificate)                          // modifie le certificat avant signature
	after  func(c *ssh.Certificate)                          // modifie le certificat après signature (signature invalide)
	signer ssh.Signer                                        // autre CA si non nil
	reply  func(w http.ResponseWriter, r *http.Request) bool // réponse piégée, true si traitée
}

func newFakeCA(t *testing.T) *fakeCA {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	caPub, _ := ssh.NewPublicKey(pub)
	f := &fakeCA{t: t, prov: newProvKey(t), caKey: priv, caPub: caPub, jtis: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /1.0/ssh/roots", func(w http.ResponseWriter, r *http.Request) {
		if f.reply != nil && f.reply(w, r) {
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"userKey": []string{base64.StdEncoding.EncodeToString(f.caPub.Marshal())}})
	})
	mux.HandleFunc("POST /1.0/ssh/sign", f.handleSign)
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCA) root(t testing.TB) string {
	return writeFile(t, "root.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})), 0o644)
}

func (f *fakeCA) client(t *testing.T) *caClient {
	t.Helper()
	c, err := newCAClient(context.Background(), CAConfig{URL: f.srv.URL, RootFile: f.root(t)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *fakeCA) handleSign(w http.ResponseWriter, r *http.Request) {
	if f.reply != nil && f.reply(w, r) {
		return
	}
	var body struct {
		PublicKey   []byte   `json:"publicKey"`
		OTT         string   `json:"ott"`
		CertType    string   `json:"certType"`
		KeyID       string   `json:"keyID"`
		Principals  []string `json:"principals"`
		ValidBefore string   `json:"validBefore"`
	}
	raw := map[string]any{}
	dec := json.NewDecoder(r.Body)
	var b json.RawMessage
	if err := dec.Decode(&b); err != nil {
		http.Error(w, "bad", 400)
		return
	}
	_ = json.Unmarshal(b, &body)
	_ = json.Unmarshal(b, &raw)

	tok, err := jwt.ParseSigned(body.OTT, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		http.Error(w, "token", http.StatusUnauthorized)
		return
	}
	var cl jwt.Claims
	var extra struct {
		Step struct {
			SSH map[string]any `json:"ssh"`
		} `json:"step"`
	}
	if err := tok.Claims(&f.prov.priv.PublicKey, &cl, &extra); err != nil {
		http.Error(w, "signature", http.StatusUnauthorized)
		return
	}
	if err := cl.ValidateWithLeeway(jwt.Expected{Issuer: provName, Time: time.Now()}, time.Minute); err != nil {
		http.Error(w, "claims", http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	replay := f.jtis[cl.ID]
	f.jtis[cl.ID] = true
	f.headers = append(f.headers, tok.Headers[0])
	f.claims = append(f.claims, cl)
	f.steps = append(f.steps, extra.Step.SSH)
	f.bodies = append(f.bodies, raw)
	f.mu.Unlock()
	if replay || cl.ID == "" || !cl.Audience.Contains(f.srv.URL+"/1.0/ssh/sign") || cl.Subject != body.KeyID {
		http.Error(w, "refusé", http.StatusUnauthorized)
		return
	}
	pub, err := ssh.ParsePublicKey(body.PublicKey)
	if err != nil {
		http.Error(w, "clé", 400)
		return
	}
	d, _ := time.ParseDuration(body.ValidBefore)
	now := time.Now()
	cert := &ssh.Certificate{
		Key: pub, Serial: 7, CertType: ssh.UserCert, KeyId: body.KeyID, ValidPrincipals: body.Principals,
		ValidAfter: uint64(now.Add(-time.Minute).Unix()), ValidBefore: uint64(now.Add(d).Unix()),
		Permissions: ssh.Permissions{Extensions: map[string]string{"permit-pty": ""}},
	}
	if f.before != nil {
		f.before(cert)
	}
	s := f.signer
	if s == nil {
		s, _ = ssh.NewSignerFromKey(f.caKey)
	}
	if err := cert.SignCert(rand.Reader, s); err != nil {
		http.Error(w, "sign", 500)
		return
	}
	if f.after != nil {
		f.after(cert)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"crt": base64.StdEncoding.EncodeToString(cert.Marshal())})
}

// unrelatedRoot: une racine auto-signée sans lien avec le serveur testé (les serveurs httptest partagent tous le même certificat).
func unrelatedRoot(t testing.TB) string {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "autre racine"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, "autre.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), 0o644)
}

func validRequest(t testing.TB) *validated {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(pub)
	return &validated{Key: k, Principal: "ops", KeyID: "warpgate:alice:42", TTL: 5 * time.Minute}
}

func TestLoadRoleSigner(t *testing.T) {
	p := newProvKey(t)
	if _, err := loadRoleSigner(p.role); err != nil {
		t.Fatalf("clé valide refusée: %v", err)
	}
	mk := func(plain []byte, pw string) RoleConfig {
		r := p.role
		r.KeyFile = writeFile(t, "k", encryptJWK(t, plain, pw), 0o600)
		return r
	}
	pubOnly, _ := json.Marshal(jose.JSONWebKey{Key: &p.priv.PublicKey, KeyID: "k", Algorithm: "ES256"})
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaJWK, _ := json.Marshal(jose.JSONWebKey{Key: rsaKey, KeyID: "k", Algorithm: "RS256"})
	noKid, _ := json.Marshal(jose.JSONWebKey{Key: p.priv, Algorithm: "ES256"})
	oct, _ := json.Marshal(jose.JSONWebKey{Key: []byte("0123456789abcdef0123456789abcdef"), KeyID: "k", Algorithm: "HS256"})
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384es256, _ := json.Marshal(jose.JSONWebKey{Key: p384, KeyID: "k", Algorithm: "ES256"})

	wrongPw := p.role
	wrongPw.PasswordFile = writeFile(t, "pw", "autre mot de passe", 0o600)
	garbage := p.role
	garbage.KeyFile = writeFile(t, "k", "pas un JWE", 0o600)
	missing := p.role
	missing.KeyFile = filepath.Join(t.TempDir(), "absent")

	cases := map[string]RoleConfig{
		"mauvais mot de passe":     wrongPw,
		"fichier illisible":        garbage,
		"fichier absent":           missing,
		"clé publique seulement":   mk(pubOnly, provPassword),
		"clé RSA":                  mk(rsaJWK, provPassword),
		"clé sans kid":             mk(noKid, provPassword),
		"clé symétrique HS256":     mk(oct, provPassword),
		"courbe et alg en conflit": mk(p384es256, provPassword),
	}
	for name, role := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := loadRoleSigner(role); err == nil {
				t.Fatal("aurait dû être refusé")
			}
		})
	}
}

func TestSignHappyPathAndTokenClaims(t *testing.T) {
	f := newFakeCA(t)
	c := f.client(t)
	rs, err := loadRoleSigner(f.prov.role)
	if err != nil {
		t.Fatal(err)
	}
	v := validRequest(t)
	cert, err := c.sign(context.Background(), rs, v)
	if err != nil {
		t.Fatal(err)
	}
	if cert.KeyId != v.KeyID || len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "ops" {
		t.Fatalf("certificat inattendu: %+v", cert)
	}
	// Un deuxième appel doit passer: chaque jeton a un jti unique (la fausse CA refuse les rejeux).
	if _, err := c.sign(context.Background(), rs, v); err != nil {
		t.Fatalf("deuxième émission: %v", err)
	}
	cl, hd, step := f.claims[0], f.headers[0], f.steps[0]
	if cl.Issuer != provName || cl.Subject != v.KeyID || !cl.Audience.Contains(f.srv.URL+"/1.0/ssh/sign") {
		t.Fatalf("claims: %+v", cl)
	}
	if life := cl.Expiry.Time().Sub(cl.IssuedAt.Time()); life != tokenLifetime {
		t.Fatalf("durée de vie du jeton %v", life)
	}
	if hd.KeyID != f.prov.kid || hd.Algorithm != "ES256" {
		t.Fatalf("en-tête: %+v", hd)
	}
	if step["certType"] != "user" || step["keyID"] != v.KeyID || step["validBefore"] != "5m0s" {
		t.Fatalf("options step.ssh: %v", step)
	}
	if ps, _ := step["principals"].([]any); len(ps) != 1 || ps[0] != "ops" {
		t.Fatalf("principals du jeton: %v", step["principals"])
	}
	if f.claims[0].ID == f.claims[1].ID {
		t.Fatal("jti réutilisé")
	}
}

// Le certificat renvoyé par la CA est la dernière barrière: chaque écart doit être refusé.
func TestSignRejectsBadCertificates(t *testing.T) {
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	_ = otherPub
	otherSigner, _ := ssh.NewSignerFromKey(otherPriv)
	strangerPub, _, _ := ed25519.GenerateKey(rand.Reader)
	strangerKey, _ := ssh.NewPublicKey(strangerPub)

	cases := map[string]func(f *fakeCA){
		"certificat d'hôte":      func(f *fakeCA) { f.before = func(c *ssh.Certificate) { c.CertType = ssh.HostCert } },
		"autre clé publique":     func(f *fakeCA) { f.before = func(c *ssh.Certificate) { c.Key = strangerKey } },
		"autre key id":           func(f *fakeCA) { f.before = func(c *ssh.Certificate) { c.KeyId = "warpgate:mallory:1" } },
		"principal différent":    func(f *fakeCA) { f.before = func(c *ssh.Certificate) { c.ValidPrincipals = []string{"postgres"} } },
		"principals en plus":     func(f *fakeCA) { f.before = func(c *ssh.Certificate) { c.ValidPrincipals = []string{"ops", "root"} } },
		"aucun principal (tous)": func(f *fakeCA) { f.before = func(c *ssh.Certificate) { c.ValidPrincipals = nil } },
		"sans expiration":        func(f *fakeCA) { f.before = func(c *ssh.Certificate) { c.ValidBefore = ssh.CertTimeInfinity } },
		"validité trop longue": func(f *fakeCA) {
			f.before = func(c *ssh.Certificate) { c.ValidBefore = uint64(time.Now().Add(time.Hour).Unix()) }
		},
		"validité au-delà de int64": func(f *fakeCA) { f.before = func(c *ssh.Certificate) { c.ValidBefore = 1<<63 + 10 } },
		"déjà expiré": func(f *fakeCA) {
			f.before = func(c *ssh.Certificate) { c.ValidAfter = 1; c.ValidBefore = uint64(time.Now().Add(-time.Hour).Unix()) }
		},
		"pas encore valide": func(f *fakeCA) {
			f.before = func(c *ssh.Certificate) { c.ValidAfter = uint64(time.Now().Add(time.Hour).Unix()) }
		},
		"force-command": func(f *fakeCA) {
			f.before = func(c *ssh.Certificate) { c.CriticalOptions = map[string]string{"force-command": "/bin/sh"} }
		},
		"extension permit-port-forwarding": func(f *fakeCA) {
			f.before = func(c *ssh.Certificate) {
				c.Extensions = map[string]string{"permit-pty": "", "permit-port-forwarding": ""}
			}
		},
		"extension permit-agent-forwarding": func(f *fakeCA) {
			f.before = func(c *ssh.Certificate) { c.Extensions = map[string]string{"permit-agent-forwarding": ""} }
		},
		"extension permit-X11-forwarding": func(f *fakeCA) {
			f.before = func(c *ssh.Certificate) { c.Extensions = map[string]string{"permit-X11-forwarding": ""} }
		},
		"extension permit-user-rc": func(f *fakeCA) {
			f.before = func(c *ssh.Certificate) { c.Extensions = map[string]string{"permit-pty": "", "permit-user-rc": ""} }
		},
		"extension inconnue": func(f *fakeCA) {
			f.before = func(c *ssh.Certificate) { c.Extensions = map[string]string{"x-evil@example": ""} }
		},
		"option critique inconnue": func(f *fakeCA) {
			f.before = func(c *ssh.Certificate) { c.CriticalOptions = map[string]string{"x-evil": ""} }
		},
		"signé par une autre CA": func(f *fakeCA) { f.signer = otherSigner },
		"altéré après signature": func(f *fakeCA) {
			f.after = func(c *ssh.Certificate) { c.Extensions = map[string]string{"permit-port-forwarding": ""} }
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFakeCA(t)
			setup(f)
			c := f.client(t)
			rs, _ := loadRoleSigner(f.prov.role)
			if cert, err := c.sign(context.Background(), rs, validRequest(t)); err == nil {
				t.Fatalf("certificat accepté: %+v", cert)
			}
		})
	}
}

func TestSignCAFailures(t *testing.T) {
	const secret = "SECRET-DU-CORPS-DE-LA-CA"
	cases := map[string]func(w http.ResponseWriter, r *http.Request) bool{
		"statut 500": func(w http.ResponseWriter, r *http.Request) bool { http.Error(w, secret, 500); return true },
		"statut 403": func(w http.ResponseWriter, r *http.Request) bool {
			http.Error(w, secret, http.StatusForbidden)
			return true
		},
		"JSON invalide": func(w http.ResponseWriter, r *http.Request) bool { _, _ = w.Write([]byte("{" + secret)); return true },
		"crt absent": func(w http.ResponseWriter, r *http.Request) bool {
			_, _ = w.Write([]byte(`{"x":"` + secret + `"}`))
			return true
		},
		"crt pas en base64": func(w http.ResponseWriter, r *http.Request) bool {
			_, _ = w.Write([]byte(`{"crt":"!!!` + secret + `"}`))
			return true
		},
		"crt n'est pas un certificat": func(w http.ResponseWriter, r *http.Request) bool {
			pub, _, _ := ed25519.GenerateKey(rand.Reader)
			k, _ := ssh.NewPublicKey(pub)
			_ = json.NewEncoder(w).Encode(map[string]string{"crt": base64.StdEncoding.EncodeToString(k.Marshal())})
			return true
		},
		"réponse énorme": func(w http.ResponseWriter, r *http.Request) bool {
			_, _ = w.Write([]byte(`{"crt":"` + strings.Repeat("A", maxCAResponse+10) + `"}`))
			return true
		},
		"redirection": func(w http.ResponseWriter, r *http.Request) bool {
			http.Redirect(w, r, "/ailleurs", http.StatusTemporaryRedirect)
			return true
		},
	}
	for name, reply := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFakeCA(t)
			c := f.client(t) // le démarrage (roots) réussit, puis la CA devient hostile
			f.reply = func(w http.ResponseWriter, r *http.Request) bool { return reply(w, r) }
			rs, _ := loadRoleSigner(f.prov.role)
			_, err := c.sign(context.Background(), rs, validRequest(t))
			if err == nil {
				t.Fatal("aurait dû échouer")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("le corps de la CA fuit dans l'erreur: %v", err)
			}
		})
	}
}

func TestSignHonorsContext(t *testing.T) {
	f := newFakeCA(t)
	c := f.client(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f.reply = func(w http.ResponseWriter, r *http.Request) bool { <-release; return true }
	rs, _ := loadRoleSigner(f.prov.role)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.sign(ctx, rs, validRequest(t)); err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("le contexte n'est pas respecté (err=%v, %v)", err, time.Since(start))
	}
}

func TestNewCAClientStartup(t *testing.T) {
	f := newFakeCA(t)
	// Racine épinglée: un serveur dont le certificat n'est pas signé par la racine configurée est refusé.
	if _, err := newCAClient(context.Background(), CAConfig{URL: f.srv.URL, RootFile: unrelatedRoot(t)}); err == nil {
		t.Error("certificat du serveur non épinglé accepté")
	}
	if _, err := newCAClient(context.Background(), CAConfig{URL: f.srv.URL, RootFile: writeFile(t, "r", "pas un pem", 0o644)}); err == nil {
		t.Error("racine illisible acceptée")
	}
	for name, body := range map[string]string{
		"aucune clé":      `{"userKey":[]}`,
		"base64 invalide": `{"userKey":["***"]}`,
		"clé illisible":   `{"userKey":["` + base64.StdEncoding.EncodeToString([]byte("nope")) + `"]}`,
	} {
		f.reply = func(w http.ResponseWriter, r *http.Request) bool { _, _ = w.Write([]byte(body)); return true }
		if _, err := newCAClient(context.Background(), CAConfig{URL: f.srv.URL, RootFile: f.root(t)}); err == nil {
			t.Errorf("%s: aurait dû échouer", name)
		}
	}
}

// Le modèle SSH normal (permit-pty seule) ou sans aucune extension reste accepté.
func TestSignAcceptsPermitPtyOnlyOrNoExtension(t *testing.T) {
	for name, ext := range map[string]map[string]string{"permit-pty": {"permit-pty": ""}, "aucune": nil} {
		t.Run(name, func(t *testing.T) {
			f := newFakeCA(t)
			f.before = func(c *ssh.Certificate) { c.Extensions = ext }
			rs, _ := loadRoleSigner(f.prov.role)
			if _, err := f.client(t).sign(context.Background(), rs, validRequest(t)); err != nil {
				t.Fatal(err)
			}
		})
	}
}
