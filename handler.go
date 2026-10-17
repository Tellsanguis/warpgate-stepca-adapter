package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	maxBody         = 8 << 10
	maxTokenLen     = 512
	failedAuthLimit = 30 // échecs d'authentification par minute avant de répondre 429
	signTimeout     = 20 * time.Second
)

// server émule les deux appels Vault dont Warpgate a besoin, et rien d'autre.
type server struct {
	cfg       *Config
	ca        *caClient
	signers   map[string]*roleSigner
	tokens    []tokenEntry
	log       *slog.Logger
	signLimit *limiter
	failLimit *limiter
	now       func() time.Time
}

type tokenEntry struct {
	name  string
	hash  [sha256.Size]byte
	roles map[string]bool
}

func newServer(cfg *Config, ca *caClient, signers map[string]*roleSigner, log *slog.Logger) *server {
	s := &server{
		cfg: cfg, ca: ca, signers: signers, log: log, now: time.Now,
		signLimit: &limiter{max: cfg.RatePerMinute}, failLimit: &limiter{max: failedAuthLimit},
	}
	for _, t := range cfg.Tokens {
		e := tokenEntry{name: t.Name, roles: map[string]bool{}}
		h, _ := hex.DecodeString(t.SHA256) // déjà validé par la configuration
		copy(e.hash[:], h)
		for _, r := range t.Roles {
			e.roles[r] = true
		}
		s.tokens = append(s.tokens, e)
	}
	return s
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"status":"ok"}`)) })
	mux.HandleFunc("GET /v1/auth/token/lookup-self", s.handleLookupSelf)
	mux.HandleFunc("POST /v1/{mount}/sign/{role}", s.handleSign)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { writeErrors(w, http.StatusNotFound) })
	return s.wrap(mux)
}

// wrap pose les en-têtes de sécurité, borne le corps et empêche qu'une panique révèle quoi que ce soit.
func (s *server) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Type", "application/json")
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		defer func() {
			if p := recover(); p != nil {
				s.log.Error("panic", "event", "panic", "path", r.URL.Path) // pas de valeur ni de pile dans la réponse
				writeErrors(w, http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// authenticate compare l'empreinte du jeton à toutes les empreintes configurées, sans sortie anticipée.
func (s *server) authenticate(r *http.Request) *tokenEntry {
	tok := r.Header.Get("X-Vault-Token")
	if tok == "" || len(tok) > maxTokenLen {
		return nil
	}
	sum := sha256.Sum256([]byte(tok))
	var found *tokenEntry
	for i := range s.tokens {
		if subtle.ConstantTimeCompare(sum[:], s.tokens[i].hash[:]) == 1 {
			found = &s.tokens[i]
		}
	}
	return found
}

// deny répond identiquement pour un jeton absent, faux ou sans droit sur le rôle (pas d'oracle).
func (s *server) deny(w http.ResponseWriter, r *http.Request, rid, reason string) {
	if !s.failLimit.allow(s.now()) {
		s.audit(r, rid, "auth", "denied", "trop_d_echecs")
		writeErrors(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}
	s.audit(r, rid, "auth", "denied", reason)
	writeErrors(w, http.StatusForbidden, "permission denied")
}

func (s *server) handleLookupSelf(w http.ResponseWriter, r *http.Request) {
	rid := requestID()
	tok := s.authenticate(r)
	if tok == nil {
		s.deny(w, r, rid, "jeton_invalide")
		return
	}
	s.audit(r, rid, "lookup", "ok", "", "token", tok.name)
	// Champs exigés par vaultrs (LookupTokenResponse). `id` reste vide: ne jamais renvoyer le jeton.
	writeJSON(w, http.StatusOK, vaultEnvelope(rid, map[string]any{
		"accessor": "", "creation_time": 0, "creation_ttl": 0, "display_name": tok.name, "entity_id": "",
		"expire_time": nil, "explicit_max_ttl": 0, "id": "", "identity_policies": nil, "issue_time": "",
		"meta": nil, "num_uses": 0, "orphan": true, "path": "auth/token/create", "policies": []string{"default"},
		"renewable": false, "ttl": 0,
	}))
}

func (s *server) handleSign(w http.ResponseWriter, r *http.Request) {
	rid := requestID()
	start := s.now()
	tok := s.authenticate(r)
	roleName := r.PathValue("role")
	rc, known := s.cfg.Roles[roleName]
	if tok == nil || !known || !tok.roles[roleName] {
		s.deny(w, r, rid, "jeton_ou_role_refuse")
		return
	}
	fields := []any{"token", tok.name, "role", roleName}
	fail := func(status int, result, reason string, extra ...any) {
		s.audit(r, rid, "sign", result, reason, append(fields, extra...)...)
		writeErrors(w, status, map[int]string{400: "invalid request", 404: "unsupported path", 415: "unsupported media type",
			429: "rate limit exceeded", 502: "upstream error"}[status])
	}
	if r.PathValue("mount") != s.cfg.Mount {
		fail(http.StatusNotFound, "denied", "mount_inconnu")
		return
	}
	// Warpgate (vaultrs) n'envoie aucun Content-Type, comme avec un vrai Vault: absent ou JSON, tout autre type est refusé.
	if ct := r.Header.Get("Content-Type"); ct != "" {
		if mt, _, err := mime.ParseMediaType(ct); err != nil || mt != "application/json" {
			fail(http.StatusUnsupportedMediaType, "denied", "content_type", "content_type", truncate(ct, 64))
			return
		}
	}
	if !s.signLimit.allow(s.now()) {
		fail(http.StatusTooManyRequests, "denied", "limite_de_debit")
		return
	}
	v, err := parseSignRequest(r.Body, rc)
	if err != nil {
		reason := "requete"
		if re, ok := err.(reqError); ok {
			reason = string(re)
		}
		fail(http.StatusBadRequest, "denied", reason)
		return
	}
	fields = append(fields, "principal", v.Principal, "key_id", v.KeyID, "key_fp", ssh.FingerprintSHA256(v.Key))
	ctx, cancel := context.WithTimeout(r.Context(), signTimeout)
	defer cancel()
	cert, err := s.ca.sign(ctx, s.signers[roleName], v)
	if err != nil {
		// Le détail reste dans le journal (sans secret); le client ne reçoit qu'un message générique.
		fail(http.StatusBadGateway, "error", "ca", "detail", err.Error())
		return
	}
	s.audit(r, rid, "sign", "ok", "", append(fields, "serial", strconv.FormatUint(cert.Serial, 10), "valid_before", cert.ValidBefore,
		"ms", s.now().Sub(start).Milliseconds())...)
	writeJSON(w, http.StatusOK, vaultEnvelope(rid, map[string]any{
		"serial_number": strconv.FormatUint(cert.Serial, 10),
		"signed_key":    strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert))),
	}))
}

// audit n'écrit jamais d'en-tête, de jeton ni de clé publique complète.
func (s *server) audit(r *http.Request, rid, event, result, reason string, kv ...any) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	args := append([]any{"event", event, "result", result, "reason", reason, "rid", rid, "remote", host}, kv...)
	level := slog.LevelInfo
	if result != "ok" {
		level = slog.LevelWarn
	}
	s.log.Log(r.Context(), level, "audit", args...)
}

func vaultEnvelope(rid string, data any) map[string]any {
	return map[string]any{
		"request_id": rid, "lease_id": "", "renewable": false, "lease_duration": 0,
		"data": data, "wrap_info": nil, "warnings": nil, "auth": nil,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErrors(w http.ResponseWriter, status int, msgs ...string) {
	if msgs == nil || msgs[0] == "" {
		msgs = []string{}
	}
	writeJSON(w, status, map[string][]string{"errors": msgs})
}

func requestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// limiter: fenêtre fixe d'une minute, suffisant pour borner le trafic vers la CA.
type limiter struct {
	mu    sync.Mutex
	max   int
	start time.Time
	n     int
}

func (l *limiter) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.start) >= time.Minute {
		l.start, l.n = now, 0
	}
	if l.n >= l.max {
		return false
	}
	l.n++
	return true
}

// truncate borne une valeur fournie par le client avant de la journaliser.
func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
