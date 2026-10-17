//go:build e2e

// Bout en bout: client SSH -> Warpgate 0.30.0 réel -> adaptateur -> step-ca réel, puis sshd cible qui ne fait confiance qu'à la CA de test.
// Lancé par integration/run.sh (E2E=1). Les preuves côté sshd et adaptateur sont vérifiées par run.sh dans les journaux des conteneurs.
package e2e

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	wgAPI       = os.Getenv("WG_API")
	wgSSH       = os.Getenv("WG_SSH")
	wgToken     = os.Getenv("WG_TOKEN")
	wgPassword  = os.Getenv("WG_ADMIN_PASSWORD")
	adapterTok  = os.Getenv("ADAPTER_TOKEN")
	adapterURL  = os.Getenv("ADAPTER_URL")
	skipVerify  = os.Getenv("WG_BACKEND_SKIP_VERIFY") == "1"
	phaseDown   = os.Getenv("E2E_PHASE") == "down"
	httpTimeout = 20 * time.Second
)

// api appelle l'API d'administration de Warpgate (certificat auto-signé: test seulement).
func api(t testing.TB, method, path string, body, out any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, wgAPI+"/@warpgate/admin/api"+path, rd)
	req.Header.Set("X-Warpgate-Token", wgToken)
	req.Header.Set("Content-Type", "application/json")
	c := &http.Client{Timeout: httpTimeout, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // #nosec G402 -- Warpgate de test auto-signé
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		t.Fatalf("%s %s: HTTP %d %s", method, path, resp.StatusCode, raw)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("%s %s: réponse illisible: %v (%s)", method, path, err, raw)
		}
	}
}

type idResp struct {
	ID string `json:"id"`
}

func certTarget(name, host, user, backend, role string) map[string]any {
	return map[string]any{
		"name": name, "ticket_requests_disabled": true, "ticket_require_approval": false, "require_approval": false,
		"options": map[string]any{
			"kind": "Ssh", "host": host, "port": 22, "username": user, "allow_insecure_algos": false,
			"auth": map[string]any{"kind": "Certificate", "backend": backend, "mount": "ssh", "role": role},
		},
	}
}

var backendIDs = map[string]string{}

// provision configure Warpgate comme le ferait un administrateur: backends Vault vers l'adaptateur, rôle, cibles.
func provision(t *testing.T) {
	t.Helper()
	// stepca-verify (vérification TLS active) n'est utilisé par aucune cible: il documente la limite de Warpgate 0.30.0.
	for name, c := range map[string]struct {
		paths []string
		skip  bool
	}{"stepca": {[]string{"ssh/sign/ops"}, skipVerify}, "stepca-open": {[]string{}, skipVerify}, "stepca-verify": {[]string{}, false}} {
		var b idResp
		api(t, "POST", "/secret-backends", map[string]any{
			"name": name, "backend_type": "vault", "address": adapterURL,
			"auth": map[string]any{"method": "Token", "token": adapterTok}, "tls_skip_verify": c.skip, "allowed_paths": c.paths,
		}, &b)
		backendIDs[name] = b.ID
	}
	var role idResp
	api(t, "POST", "/roles", map[string]any{"name": "ops-access"}, &role)
	var users []struct{ ID, Username string }
	api(t, "GET", "/users", nil, &users)
	var admin string
	for _, u := range users {
		if u.Username == "admin" {
			admin = u.ID
		}
	}
	if admin == "" {
		t.Fatal("utilisateur admin introuvable")
	}
	api(t, "POST", "/users/"+admin+"/roles/"+role.ID, nil, nil)
	for _, tg := range []map[string]any{
		certTarget("sshd-target", "sshd-target", "ops", "stepca", "ops"),
		certTarget("sshd-badprincipal", "sshd-target", "postgres", "stepca", "ops"),
		certTarget("sshd-forbiddenrole", "sshd-target", "ops", "stepca-open", "presta"),
		certTarget("sshd-blockedpath", "sshd-target", "ops", "stepca", "presta"),
	} {
		var created idResp
		api(t, "POST", "/targets", tg, &created)
		api(t, "POST", "/targets/"+created.ID+"/roles/"+role.ID, nil, nil)
	}
}

func TestMain(m *testing.M) {
	if wgAPI == "" || wgSSH == "" {
		fmt.Println("variables d'environnement manquantes: lancer via integration/run.sh")
		os.Exit(2)
	}
	os.Exit(m.Run())
}

func TestProvisionAndBackendHealth(t *testing.T) {
	if phaseDown {
		t.Skip("phase adaptateur arrêté")
	}
	provision(t)
	for name, id := range backendIDs {
		if name == "stepca-verify" {
			continue
		}
		var h struct {
			Error *string `json:"error"`
		}
		api(t, "POST", "/secret-backends/"+id+"/health", nil, &h)
		if h.Error != nil {
			t.Fatalf("le backend %s ne joint pas l'adaptateur: %s", name, *h.Error)
		}
	}
}

// Limite connue de Warpgate 0.30.0: le client Vault ne sait pas faire confiance à une CA privée (racines publiques intégrées, aucune option).
// Si ce test échoue, Warpgate a ajouté cette option: mettre à jour la doc et activer la vérification TLS vers l'adaptateur.
func TestKnownLimitationWarpgateCannotTrustPrivateCA(t *testing.T) {
	if phaseDown {
		t.Skip("phase adaptateur arrêté")
	}
	var h struct {
		Error *string `json:"error"`
	}
	api(t, "POST", "/secret-backends/"+backendIDs["stepca-verify"]+"/health", nil, &h)
	if h.Error == nil {
		t.Fatal("Warpgate fait désormais confiance à la CA de test: la limite n'existe plus, mettre à jour la documentation")
	}
	t.Logf("limite confirmée, la vérification TLS échoue: %s", *h.Error)
}

// run ouvre une session SSH via Warpgate vers la cible demandée et exécute une commande.
func run(target, cmd string) (string, error) {
	cfg := &ssh.ClientConfig{
		User:            "admin:" + target,
		Auth:            []ssh.AuthMethod{ssh.Password(wgPassword)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106 -- Warpgate de test, clé d'hôte éphémère
		Timeout:         20 * time.Second,
	}
	conn, err := ssh.Dial("tcp", wgSSH, cfg)
	if err != nil {
		return "", fmt.Errorf("connexion: %w", err)
	}
	defer conn.Close()
	s, err := conn.NewSession()
	if err != nil {
		return "", fmt.Errorf("session: %w", err)
	}
	defer s.Close()
	out, err := s.CombinedOutput(cmd)
	return string(out), err
}

func TestSessionThroughWarpgateUsesCertificate(t *testing.T) {
	if phaseDown {
		t.Skip("phase adaptateur arrêté")
	}
	for i := 0; i < 2; i++ { // deux sessions: deux certificats distincts
		out, err := run("sshd-target", "id -un")
		if err != nil || strings.TrimSpace(out) != "ops" {
			t.Fatalf("session %d: sortie %q, erreur %v", i+1, out, err)
		}
	}
}

// Les trois cibles piégées doivent échouer sans jamais atteindre le compte demandé.
func TestDeniedTargetsNeverReachTheHost(t *testing.T) {
	if phaseDown {
		t.Skip("phase adaptateur arrêté")
	}
	for _, target := range []string{"sshd-badprincipal", "sshd-forbiddenrole", "sshd-blockedpath"} {
		out, err := run(target, "id -un")
		if err == nil {
			t.Errorf("%s: la session a réussi (sortie %q)", target, out)
		}
	}
}

// Phase 2 (run.sh a arrêté l'adaptateur): aucune connexion ne doit aboutir, pas de repli sur une autre clé.
func TestFailsClosedWhenAdapterIsDown(t *testing.T) {
	if !phaseDown {
		t.Skip("phase normale")
	}
	if out, err := run("sshd-target", "id -un"); err == nil {
		t.Fatalf("la session a réussi sans adaptateur (sortie %q)", out)
	}
}
