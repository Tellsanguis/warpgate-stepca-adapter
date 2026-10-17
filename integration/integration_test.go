//go:build integration

// Tests d'intégration: adaptateur réel (conteneur durci) + step-ca réel (image de production), réseau Docker interne.
// Lancés par integration/run.sh, jamais contre la CA de production.
package integration

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/crypto/ssh"
)

var (
	adapterURL = os.Getenv("ADAPTER_URL")
	caURL      = os.Getenv("CA_URL")
	work       = os.Getenv("WORK")
)

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(work, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func httpClient(t *testing.T, rootFile string, maxVersion uint16) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(readFile(t, rootFile)) {
		t.Fatalf("racine illisible: %s", rootFile)
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MaxVersion: maxVersion}}}
}

func token(t *testing.T) string { return strings.TrimSpace(string(readFile(t, "token"))) }

func newKey(t *testing.T) (ssh.PublicKey, string) {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(pub)
	return k, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

func post(t *testing.T, c *http.Client, url, tok string, body any) (int, []byte) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if tok != "" {
		req.Header.Set("X-Vault-Token", tok)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func signViaAdapter(t *testing.T, tok string, body map[string]any) (int, []byte) {
	return post(t, httpClient(t, "tls.crt", tls.VersionTLS13), adapterURL+"/v1/ssh/sign/ops", tok, body)
}

func goodBody(pub string) map[string]any {
	return map[string]any{"public_key": pub, "cert_type": "user", "valid_principals": "ops", "key_id": "warpgate:alice:it-1", "ttl": "5m"}
}

func caUserKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	resp, err := httpClient(t, "root_ca.crt", tls.VersionTLS13).Get(caURL + "/1.0/ssh/roots")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var roots struct {
		UserKey []string `json:"userKey"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&roots); err != nil || len(roots.UserKey) == 0 {
		t.Fatalf("clé CA: %v", err)
	}
	blob, _ := base64.StdEncoding.DecodeString(roots.UserKey[0])
	k, err := ssh.ParsePublicKey(blob)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestHappyPathAgainstRealCA(t *testing.T) {
	pub, line := newKey(t)
	ca := caUserKey(t)
	status, body := signViaAdapter(t, token(t), goodBody(line))
	if status != 200 {
		t.Fatalf("statut %d: %s", status, body)
	}
	var resp struct {
		Data struct {
			Key    string `json:"signed_key"`
			Serial string `json:"serial_number"`
		} `json:"data"`
	}
	_ = json.Unmarshal(body, &resp)
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Data.Key))
	cert, ok := parsed.(*ssh.Certificate)
	if err != nil || !ok {
		t.Fatalf("certificat illisible: %v", err)
	}
	chk := ssh.CertChecker{IsUserAuthority: func(a ssh.PublicKey) bool { return bytes.Equal(a.Marshal(), ca.Marshal()) }}
	if err := chk.CheckCert("ops", cert); err != nil {
		t.Fatalf("certificat non valide pour ops: %v", err)
	}
	if !chk.IsUserAuthority(cert.SignatureKey) {
		t.Fatal("signé par une autre autorité que la CA")
	}
	if cert.CertType != ssh.UserCert || len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "ops" ||
		cert.KeyId != "warpgate:alice:it-1" || !bytes.Equal(cert.Key.Marshal(), pub.Marshal()) {
		t.Fatalf("contenu inattendu: %+v", cert)
	}
	if left := time.Until(time.Unix(int64(cert.ValidBefore), 0)); left < 3*time.Minute || left > 6*time.Minute {
		t.Fatalf("validité restante %v, attendue environ 5 min", left)
	}
	if _, bad := cert.Extensions["permit-port-forwarding"]; bad {
		t.Fatal("extension non prévue par le modèle")
	}
	if _, bad := cert.CriticalOptions["force-command"]; bad {
		t.Fatal("force-command présent")
	}
	// Deuxième émission avec un autre jeton JWK: la CA refuse les rejeux, donc chaque appel doit être unique.
	_, line2 := newKey(t)
	if status, body := signViaAdapter(t, token(t), goodBody(line2)); status != 200 {
		t.Fatalf("deuxième émission: %d %s", status, body)
	}
}

func TestAdapterRefusals(t *testing.T) {
	_, line := newKey(t)
	cases := map[string]struct {
		tok  string
		body map[string]any
		want int
	}{
		"sans jeton":          {"", goodBody(line), 403},
		"jeton faux":          {"s.faux", goodBody(line), 403},
		"principal root":      {token(t), mut(goodBody(line), "valid_principals", "root"), 400},
		"key_id sans préfixe": {token(t), mut(goodBody(line), "key_id", "alice@example.org"), 400},
		"ttl trop long":       {token(t), mut(goodBody(line), "ttl", "1h"), 400},
	}
	for name, c := range cases {
		if status, body := signViaAdapter(t, c.tok, c.body); status != c.want {
			t.Errorf("%s: statut %d (%s), attendu %d", name, status, body, c.want)
		}
	}
}

func mut(m map[string]any, k string, v any) map[string]any {
	out := map[string]any{}
	for kk, vv := range m {
		out[kk] = vv
	}
	out[k] = v
	return out
}

func TestAdapterRequiresTLS13(t *testing.T) {
	if _, err := httpClient(t, "tls.crt", tls.VersionTLS12).Get(adapterURL + "/healthz"); err == nil {
		t.Fatal("TLS 1.2 accepté")
	}
}

// --- Défenses de la CA elle-même, indépendantes de l'adaptateur ---

func provisionerSigner(t *testing.T, key *ecdsa.PrivateKey, kid string) jose.Signer {
	t.Helper()
	jwk := jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: "ES256"}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: &jwk}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func realProvisionerKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	enc, err := jose.ParseEncrypted(string(readFile(t, "jwk.jwe")), []jose.KeyAlgorithm{jose.PBES2_HS256_A128KW}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := enc.Decrypt(bytes.TrimSpace(readFile(t, "jwk.pw")))
	if err != nil {
		t.Fatal(err)
	}
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(plain, &jwk); err != nil {
		t.Fatal(err)
	}
	return jwk.Key.(*ecdsa.PrivateKey), jwk.KeyID
}

func rawToken(t *testing.T, s jose.Signer, keyID, principal string, jti string) string {
	t.Helper()
	now := time.Now()
	tok, err := jwt.Signed(s).Claims(jwt.Claims{
		Issuer: "warpgate-ops", Subject: keyID, Audience: jwt.Audience{caURL + "/1.0/ssh/sign"},
		IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(30 * time.Second)), ID: jti,
	}).Claims(map[string]any{"step": map[string]any{"ssh": map[string]any{
		"certType": "user", "keyID": keyID, "principals": []string{principal}, "validBefore": "5m0s",
	}}}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func caSign(t *testing.T, ott string, pub ssh.PublicKey, keyID, principal string) (int, []byte) {
	return post(t, httpClient(t, "root_ca.crt", tls.VersionTLS13), caURL+"/1.0/ssh/sign", "", map[string]any{
		"publicKey": pub.Marshal(), "ott": ott, "certType": "user", "keyID": keyID, "principals": []string{principal}, "validBefore": "5m0s",
	})
}

func ok2xx(status int) bool { return status >= 200 && status < 300 } // step-ca répond 201 à une signature

func jti() string { b := make([]byte, 16); _, _ = rand.Read(b); return hex.EncodeToString(b) }

// Si l'adaptateur était compromis et demandait root, le modèle de la CA garde le dernier mot.
func TestCATemplateHasLastWord(t *testing.T) {
	key, kid := realProvisionerKey(t)
	pub, _ := newKey(t)
	status, body := caSign(t, rawToken(t, provisionerSigner(t, key, kid), "warpgate:evil:1", "root", jti()), pub, "warpgate:evil:1", "root")
	if !ok2xx(status) {
		return // refus pur et simple: acceptable
	}
	var resp struct {
		Crt string `json:"crt"`
	}
	_ = json.Unmarshal(body, &resp)
	blob, _ := base64.StdEncoding.DecodeString(resp.Crt)
	parsed, _ := ssh.ParsePublicKey(blob)
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatalf("réponse inattendue: %s", body)
	}
	for _, p := range cert.ValidPrincipals {
		if p == "root" {
			t.Fatalf("la CA a émis un certificat root: %v", cert.ValidPrincipals)
		}
	}
	t.Logf("la CA a ramené les principals demandés (root) à %v", cert.ValidPrincipals)
}

func TestCARejectsReplayAndForeignKeys(t *testing.T) {
	key, kid := realProvisionerKey(t)
	pub, _ := newKey(t)
	s := provisionerSigner(t, key, kid)
	ott := rawToken(t, s, "warpgate:alice:2", "ops", jti())
	if status, body := caSign(t, ott, pub, "warpgate:alice:2", "ops"); !ok2xx(status) {
		t.Fatalf("jeton valide refusé: %d %s", status, body)
	}
	if status, _ := caSign(t, ott, pub, "warpgate:alice:2", "ops"); ok2xx(status) {
		t.Fatal("rejeu du même jeton accepté par la CA")
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	forged := rawToken(t, provisionerSigner(t, other, kid), "warpgate:alice:3", "ops", jti())
	if status, _ := caSign(t, forged, pub, "warpgate:alice:3", "ops"); ok2xx(status) {
		t.Fatal("jeton signé par une autre clé accepté")
	}
}
