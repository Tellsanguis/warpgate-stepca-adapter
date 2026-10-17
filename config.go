package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"time"
)

// Plafond dur: aucun rôle ne peut dépasser cette durée, quelle que soit la configuration.
const hardMaxTTL = time.Hour

var (
	reName      = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	reTokenName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	reProv      = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,64}$`)
	reHash      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	rePrincipal = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
)

type Config struct {
	Listen        string                `json:"listen"`
	TLSCert       string                `json:"tls_cert"`
	TLSKey        string                `json:"tls_key"`
	Mount         string                `json:"mount"`
	RatePerMinute int                   `json:"rate_per_minute"`
	MaxConns      int                   `json:"max_conns"`        // connexions simultanées au total (défaut 128)
	MaxConnsPerIP int                   `json:"max_conns_per_ip"` // par adresse IP source (défaut 32)
	CA            CAConfig              `json:"ca"`
	Tokens        []TokenConfig         `json:"tokens"`
	Roles         map[string]RoleConfig `json:"roles"`
}

type CAConfig struct {
	URL      string `json:"url"`
	RootFile string `json:"root_file"`
}

// TokenConfig ne contient que l'empreinte SHA-256 du jeton: le jeton lui-même n'est jamais stocké ici.
type TokenConfig struct {
	Name   string   `json:"name"`
	SHA256 string   `json:"sha256"`
	Roles  []string `json:"roles"`
}

type RoleConfig struct {
	Provisioner  string   `json:"provisioner"`
	KeyFile      string   `json:"key_file"`      // JWK privé chiffré (JWE), tel que stocké dans ca.json
	PasswordFile string   `json:"password_file"` // mot de passe du JWK
	Principals   []string `json:"principals"`
	MaxTTL       string   `json:"max_ttl"`
	maxTTL       time.Duration
}

// loadConfig refuse toute configuration douteuse: champ inconnu, fichier secret lisible par d'autres, valeur hors bornes.
func loadConfig(path string) (*Config, error) {
	f, err := os.Open(path) // #nosec G304 -- chemin donné par l'opérateur
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("configuration illisible: %w", err)
	}
	// More() ne voit pas un `}` ou `]` en trop: seul EOF prouve qu'il ne reste rien après l'objet.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("configuration: données après l'objet JSON")
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("configuration invalide: %w", err)
	}
	return &c, nil
}

func (c *Config) validate() error {
	_, port, err := net.SplitHostPort(c.Listen)
	if n, convErr := strconv.Atoi(port); err != nil || convErr != nil || n < 1 || n > 65535 {
		return fmt.Errorf("listen doit être hôte:port avec un port entre 1 et 65535")
	}
	if c.TLSCert == "" || c.TLSKey == "" {
		return fmt.Errorf("tls_cert et tls_key sont obligatoires (pas de HTTP en clair)")
	}
	if err := checkSecretFile(c.TLSKey); err != nil {
		return fmt.Errorf("tls_key: %w", err)
	}
	if !reName.MatchString(c.Mount) {
		return fmt.Errorf("mount invalide")
	}
	if c.RatePerMinute == 0 {
		c.RatePerMinute = 60
	}
	if c.RatePerMinute < 1 || c.RatePerMinute > 600 {
		return fmt.Errorf("rate_per_minute hors de 1..600")
	}
	for _, l := range []struct {
		v    *int
		def  int
		name string
	}{{&c.MaxConns, 128, "max_conns"}, {&c.MaxConnsPerIP, 32, "max_conns_per_ip"}} {
		if *l.v == 0 {
			*l.v = l.def
		}
		if *l.v < 1 || *l.v > 10000 {
			return fmt.Errorf("%s hors de 1..10000", l.name)
		}
	}
	u, err := url.Parse(c.CA.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("ca.url doit être https://hôte[:port] sans chemin")
	}
	if c.CA.RootFile == "" {
		return fmt.Errorf("ca.root_file est obligatoire (la racine de la CA est épinglée)")
	}
	if len(c.Roles) == 0 || len(c.Tokens) == 0 {
		return fmt.Errorf("au moins un rôle et un jeton sont requis")
	}
	for name, r := range c.Roles {
		if err := r.validate(name); err != nil {
			return fmt.Errorf("rôle %q: %w", name, err)
		}
		c.Roles[name] = r
	}
	seenName, seenHash := map[string]bool{}, map[string]bool{}
	for _, t := range c.Tokens {
		if !reTokenName.MatchString(t.Name) || seenName[t.Name] {
			return fmt.Errorf("jeton %q: nom invalide ou en double", t.Name)
		}
		if !reHash.MatchString(t.SHA256) || seenHash[t.SHA256] {
			return fmt.Errorf("jeton %q: sha256 invalide (64 hexa minuscules) ou en double", t.Name)
		}
		if len(t.Roles) == 0 {
			return fmt.Errorf("jeton %q: aucun rôle", t.Name)
		}
		for _, r := range t.Roles {
			if _, ok := c.Roles[r]; !ok {
				return fmt.Errorf("jeton %q: rôle inconnu %q", t.Name, r)
			}
		}
		seenName[t.Name], seenHash[t.SHA256] = true, true
	}
	return nil
}

func (r *RoleConfig) validate(name string) error {
	if !reName.MatchString(name) {
		return fmt.Errorf("nom invalide")
	}
	if !reProv.MatchString(r.Provisioner) {
		return fmt.Errorf("provisioner invalide")
	}
	for _, p := range []string{r.KeyFile, r.PasswordFile} {
		if err := checkSecretFile(p); err != nil {
			return err
		}
	}
	if len(r.Principals) == 0 {
		return fmt.Errorf("aucun principal")
	}
	seen := map[string]bool{}
	for _, p := range r.Principals {
		// "root" est refusé en dur: un certificat root via le bastion est une erreur de conception.
		if !rePrincipal.MatchString(p) || p == "root" || seen[p] {
			return fmt.Errorf("principal %q invalide, interdit ou en double", p)
		}
		seen[p] = true
	}
	d, err := time.ParseDuration(r.MaxTTL)
	if err != nil || d <= 0 || d > hardMaxTTL {
		return fmt.Errorf("max_ttl doit être une durée entre 1s et %s", hardMaxTTL)
	}
	r.maxTTL = d
	return nil
}

// checkSecretFile exige un fichier ordinaire, inaccessible aux autres comptes (0600 ou plus strict).
func checkSecretFile(path string) error {
	if path == "" {
		return fmt.Errorf("chemin de fichier secret manquant")
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s n'est pas un fichier ordinaire", path)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s est lisible par d'autres comptes (mode %v, 0600 maximum)", path, st.Mode().Perm())
	}
	return nil
}
