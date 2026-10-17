package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

const (
	tokOps           = "s.token-ops-0123456789abcdefghijklmnopqrstuvwxyz"
	tokOther         = "s.token-other-0123456789abcdefghijklmnopqrstuvwxyz"
	genericForbidden = `{"errors":["permission denied"]}`
)

type harness struct {
	s    *server
	ca   *fakeCA
	logs *bytes.Buffer
}

func hashOf(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func newHarness(t *testing.T) *harness {
	t.Helper()
	f := newFakeCA(t)
	rs, err := loadRoleSigner(f.prov.role)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		Mount: "ssh", RatePerMinute: 60,
		Roles: map[string]RoleConfig{"ops": f.prov.role, "other": f.prov.role},
		Tokens: []TokenConfig{
			{Name: "warpgate", SHA256: hashOf(tokOps), Roles: []string{"ops"}},
			{Name: "autre", SHA256: hashOf(tokOther), Roles: []string{"other"}},
		},
	}
	logs := &bytes.Buffer{}
	s := newServer(cfg, f.client(t), map[string]*roleSigner{"ops": rs, "other": rs}, slog.New(slog.NewJSONHandler(logs, nil)))
	return &harness{s: s, ca: f, logs: logs}
}

func (h *harness) do(method, path, token, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.10:44444"
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	h.s.routes().ServeHTTP(rec, req)
	return rec
}

func (h *harness) sign(token, role, body string) *httptest.ResponseRecorder {
	return h.do("POST", "/v1/ssh/sign/"+role, token, "application/json", body)
}

func TestLookupSelf(t *testing.T) {
	h := newHarness(t)
	rec := h.do("GET", "/v1/auth/token/lookup-self", tokOps, "", "")
	if rec.Code != 200 {
		t.Fatalf("statut %d", rec.Code)
	}
	var env map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	// Enveloppe et champs exigés par vaultrs 0.7.4 (EndpointResult et LookupTokenResponse).
	for _, k := range []string{"data", "auth", "lease_id", "lease_duration", "renewable", "request_id", "warnings", "wrap_info"} {
		if _, ok := env[k]; !ok {
			t.Errorf("enveloppe: champ %q manquant", k)
		}
	}
	var data map[string]any
	_ = json.Unmarshal(env["data"], &data)
	for _, k := range []string{"accessor", "creation_time", "creation_ttl", "display_name", "entity_id", "explicit_max_ttl", "id",
		"issue_time", "num_uses", "orphan", "path", "policies", "renewable", "ttl"} {
		if _, ok := data[k]; !ok {
			t.Errorf("data: champ %q manquant", k)
		}
	}
	if data["renewable"] != false || data["id"] != "" {
		t.Errorf("le jeton ne doit pas être renouvelable ni renvoyé: %v", data)
	}
	if strings.Contains(rec.Body.String(), tokOps) {
		t.Fatal("le jeton est renvoyé dans la réponse")
	}
}

func TestAuthDenied(t *testing.T) {
	h := newHarness(t)
	good := body(t, nil)
	cases := map[string]*httptest.ResponseRecorder{
		"lookup sans jeton":          h.do("GET", "/v1/auth/token/lookup-self", "", "", ""),
		"lookup jeton faux":          h.do("GET", "/v1/auth/token/lookup-self", "faux", "", ""),
		"sign sans jeton":            h.sign("", "ops", good),
		"sign jeton faux":            h.sign("faux", "ops", good),
		"sign jeton trop long":       h.sign(strings.Repeat("a", 1000), "ops", good),
		"sign rôle non autorisé":     h.sign(tokOps, "other", good),
		"sign rôle inexistant":       h.sign(tokOps, "root", good),
		"sign rôle d'un autre jeton": h.sign(tokOther, "ops", good),
	}
	for name, rec := range cases {
		if rec.Code != http.StatusForbidden || strings.TrimSpace(rec.Body.String()) != genericForbidden {
			t.Errorf("%s: %d %q (réponse identique attendue pour ne pas créer d'oracle)", name, rec.Code, rec.Body.String())
		}
	}
	if len(h.ca.claims) != 0 {
		t.Fatal("la CA a été appelée malgré le refus")
	}
}

func TestSignOK(t *testing.T) {
	h := newHarness(t)
	b := body(t, nil)
	rec := h.sign(tokOps, "ops", b)
	if rec.Code != 200 {
		t.Fatalf("statut %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			Serial string `json:"serial_number"`
			Key    string `json:"signed_key"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.Data.Serial == "" {
		t.Fatalf("réponse: %v %s", err, rec.Body.String())
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Data.Key))
	cert, ok := pub.(*ssh.Certificate)
	if err != nil || !ok || cert.ValidPrincipals[0] != "ops" || cert.KeyId != "warpgate:alice:7f3c" {
		t.Fatalf("certificat renvoyé incorrect: %v %+v", err, pub)
	}
	h2 := rec.Header()
	if h2.Get("Cache-Control") != "no-store" || h2.Get("X-Content-Type-Options") != "nosniff" || h2.Get("Content-Type") != "application/json" {
		t.Errorf("en-têtes: %v", h2)
	}
}

// Warpgate envoie la requête sans Content-Type (constaté en bout en bout): elle doit passer, comme avec un vrai Vault.
func TestSignAcceptsMissingContentType(t *testing.T) {
	h := newHarness(t)
	if rec := h.do("POST", "/v1/ssh/sign/ops", tokOps, "", body(t, nil)); rec.Code != 200 {
		t.Fatalf("statut %d: %s", rec.Code, rec.Body.String())
	}
	if rec := h.do("POST", "/v1/ssh/sign/ops", tokOps, "application/json; charset=utf-8", body(t, nil)); rec.Code != 200 {
		t.Fatalf("statut %d avec charset: %s", rec.Code, rec.Body.String())
	}
}

func TestSignRejections(t *testing.T) {
	h := newHarness(t)
	cases := []struct {
		name   string
		do     func() *httptest.ResponseRecorder
		status int
	}{
		{"mauvais mount", func() *httptest.ResponseRecorder {
			return h.do("POST", "/v1/sys/sign/ops", tokOps, "application/json", body(t, nil))
		}, 404},
		{"mauvais content-type", func() *httptest.ResponseRecorder {
			return h.do("POST", "/v1/ssh/sign/ops", tokOps, "text/plain", body(t, nil))
		}, 415},
		{"content-type de formulaire", func() *httptest.ResponseRecorder {
			return h.do("POST", "/v1/ssh/sign/ops", tokOps, "application/x-www-form-urlencoded", body(t, nil))
		}, 415},
		{"méthode GET (route inconnue)", func() *httptest.ResponseRecorder { return h.do("GET", "/v1/ssh/sign/ops", tokOps, "", "") }, 404},
		{"JSON invalide", func() *httptest.ResponseRecorder { return h.sign(tokOps, "ops", `{"x`) }, 400},
		{"principal interdit", func() *httptest.ResponseRecorder {
			return h.sign(tokOps, "ops", body(t, func(m map[string]any) { m["valid_principals"] = "root" }))
		}, 400},
		{"corps trop gros", func() *httptest.ResponseRecorder { return h.sign(tokOps, "ops", strings.Repeat("a", maxBody+100)) }, 400},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := c.do()
			if rec.Code != c.status {
				t.Fatalf("statut %d, attendu %d (%s)", rec.Code, c.status, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "root") || strings.Contains(rec.Body.String(), "aaaa") {
				t.Fatalf("la réponse réécrit l'entrée: %s", rec.Body.String())
			}
		})
	}
	if len(h.ca.claims) != 0 {
		t.Fatal("la CA a été appelée pour une requête invalide")
	}
}

func TestSignUpstreamFailureIsGeneric(t *testing.T) {
	h := newHarness(t)
	const secret = "DETAIL-INTERNE-DE-LA-CA"
	h.ca.reply = func(w http.ResponseWriter, r *http.Request) bool { http.Error(w, secret, 500); return true }
	rec := h.sign(tokOps, "ops", body(t, nil))
	if rec.Code != http.StatusBadGateway || strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	h.ca.reply = nil
	h.ca.before = func(c *ssh.Certificate) { c.ValidPrincipals = []string{"ops", "root"} }
	if rec := h.sign(tokOps, "ops", body(t, nil)); rec.Code != http.StatusBadGateway || strings.Contains(rec.Body.String(), "root") {
		t.Fatalf("certificat piégé: %d %s", rec.Code, rec.Body.String())
	}
}

func TestRateLimits(t *testing.T) {
	h := newHarness(t)
	h.s.signLimit["warpgate"].max = 3
	codes := []int{}
	for i := 0; i < 4; i++ {
		codes = append(codes, h.sign(tokOps, "ops", body(t, nil)).Code)
	}
	if codes[2] != 200 || codes[3] != http.StatusTooManyRequests {
		t.Fatalf("limite de signatures: %v", codes)
	}
	// Le quota est par jeton: un jeton à l'arrêt ne prive pas l'autre (le rôle "other" est autorisé pour le jeton "autre").
	if code := h.sign(tokOther, "other", body(t, nil)).Code; code != 200 {
		t.Fatalf("le second jeton est bloqué par le quota du premier: %d", code)
	}
	// Les échecs d'authentification sont limités, mais un jeton valide continue de fonctionner (pas de blocage global).
	h2 := newHarness(t)
	var last int
	for i := 0; i < failedAuthLimit+5; i++ {
		last = h2.do("GET", "/v1/auth/token/lookup-self", "faux", "", "").Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("limite d'échecs: %d", last)
	}
	if code := h2.do("GET", "/v1/auth/token/lookup-self", tokOps, "", "").Code; code != 200 {
		t.Fatalf("un jeton valide ne doit pas être bloqué par les échecs d'autrui: %d", code)
	}
}

func TestMultipleTokensAllCompared(t *testing.T) {
	h := newHarness(t)
	// Le dernier jeton de la liste doit s'authentifier aussi (pas de sortie anticipée sur le premier).
	if code := h.do("GET", "/v1/auth/token/lookup-self", tokOther, "", "").Code; code != 200 {
		t.Fatalf("%d", code)
	}
}

func TestJournalNeverContainsSecrets(t *testing.T) {
	h := newHarness(t)
	pub := edKey(t)
	b := body(t, func(m map[string]any) { m["public_key"] = pub })
	h.sign(tokOps, "ops", b)         // succès
	h.sign("faux-"+tokOps, "ops", b) // échec d'authentification
	h.sign(tokOps, "ops", `{"x`)     // requête invalide
	out := h.logs.String()
	for _, secret := range []string{tokOps, "faux-" + tokOps, strings.Fields(pub)[1]} {
		if strings.Contains(out, secret) {
			t.Fatalf("secret dans le journal: %q", secret)
		}
	}
	for _, want := range []string{`"event":"sign"`, `"result":"ok"`, `"token":"warpgate"`, `"key_fp":"SHA256:`, `"reason":"jeton_ou_role_refuse"`, `"remote":"192.0.2.10"`} {
		if !strings.Contains(out, want) {
			t.Errorf("journal sans %s:\n%s", want, out)
		}
	}
}

func TestPanicIsContained(t *testing.T) {
	h := newHarness(t)
	srv := h.s.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { panic("jeton-secret-dans-la-panique") }))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "secret") || strings.Contains(h.logs.String(), "secret") {
		t.Fatalf("%d %s | %s", rec.Code, rec.Body.String(), h.logs.String())
	}
}

func TestUnknownPathsAndHealth(t *testing.T) {
	h := newHarness(t)
	if code := h.do("GET", "/healthz", "", "", "").Code; code != 200 {
		t.Errorf("healthz: %d", code)
	}
	for _, p := range []string{"/", "/v1/sys/health", "/v1/ssh/config/ca", "/v1/auth/token/create"} {
		if rec := h.do("GET", p, tokOps, "", ""); rec.Code != 404 && rec.Code != 405 {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
}
