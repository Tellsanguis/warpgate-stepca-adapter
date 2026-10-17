package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/crypto/ssh"
)

const (
	maxCAResponse = 64 << 10
	tokenLifetime = 30 * time.Second // le jeton JWK ne sert qu'une fois, tout de suite
	certSkew      = time.Minute      // step-ca antidate ValidAfter et arrondit les durées
)

// caClient parle à step-ca. La racine de la CA est épinglée: aucune autre autorité n'est acceptée.
type caClient struct {
	http    *http.Client
	url     string
	aud     string
	userCAs []ssh.PublicKey
	now     func() time.Time
}

// roleSigner signe les jetons du provisioner JWK d'un rôle. La clé privée n'existe qu'en mémoire.
type roleSigner struct {
	provisioner string
	signer      jose.Signer
}

func newCAClient(ctx context.Context, cfg CAConfig) (*caClient, error) {
	pem, err := os.ReadFile(cfg.RootFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("ca.root_file ne contient aucun certificat")
	}
	c := &caClient{
		http: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				Proxy:                 nil, // jamais de proxy implicite entre l'adaptateur et la CA
				TLSClientConfig:       &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
				ResponseHeaderTimeout: 10 * time.Second,
				IdleConnTimeout:       30 * time.Second,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		url: strings.TrimSuffix(cfg.URL, "/"),
		now: time.Now,
	}
	c.aud = c.url + "/1.0/ssh/sign"
	// shortcut: les clés de la CA sont lues une fois au démarrage; une rotation de la CA SSH demande un redémarrage.
	var roots struct {
		UserKey []string `json:"userKey"`
	}
	if err := c.call(ctx, http.MethodGet, "/1.0/ssh/roots", nil, &roots); err != nil {
		return nil, fmt.Errorf("lecture des clés SSH de la CA: %w", err)
	}
	for _, s := range roots.UserKey {
		blob, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, errors.New("clé SSH utilisateur de la CA illisible")
		}
		k, err := ssh.ParsePublicKey(blob)
		if err != nil {
			return nil, errors.New("clé SSH utilisateur de la CA illisible")
		}
		c.userCAs = append(c.userCAs, k)
	}
	if len(c.userCAs) == 0 {
		return nil, errors.New("la CA ne publie aucune clé SSH utilisateur")
	}
	return c, nil
}

// call fait une requête JSON, borne la réponse et ne renvoie que le code HTTP en cas d'échec (jamais le corps).
func (c *caClient) call(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.url+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req) // #nosec G107 G704 -- URL fixée par la configuration, pas par le client
	if err != nil {
		return fmt.Errorf("requête vers la CA: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxCAResponse+1))
	if err != nil || len(data) > maxCAResponse {
		return errors.New("réponse de la CA illisible ou trop grande")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("la CA répond %d", resp.StatusCode)
	}
	return json.Unmarshal(data, out)
}

// loadRoleSigner déchiffre le JWK du provisioner (JWE de ca.json) et refuse tout ce qui n'est pas une clé privée ECDSA identifiée.
func loadRoleSigner(role RoleConfig) (*roleSigner, error) {
	raw, err := os.ReadFile(role.KeyFile)
	if err != nil {
		return nil, err
	}
	pw, err := os.ReadFile(role.PasswordFile)
	if err != nil {
		return nil, err
	}
	pw = bytes.TrimRight(pw, "\r\n")
	defer clear(pw)

	enc, err := jose.ParseEncrypted(strings.TrimSpace(string(raw)),
		[]jose.KeyAlgorithm{jose.PBES2_HS256_A128KW, jose.PBES2_HS384_A192KW, jose.PBES2_HS512_A256KW},
		[]jose.ContentEncryption{jose.A128GCM, jose.A192GCM, jose.A256GCM})
	if err != nil {
		return nil, errors.New("clé JWK chiffrée illisible")
	}
	plain, err := enc.Decrypt(pw)
	if err != nil {
		return nil, errors.New("déchiffrement du JWK impossible (mot de passe incorrect ?)")
	}
	defer clear(plain)
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(plain, &jwk); err != nil || !jwk.Valid() || jwk.IsPublic() || jwk.KeyID == "" {
		return nil, errors.New("le JWK doit être une clé privée valide avec un kid")
	}
	alg := jose.SignatureAlgorithm(jwk.Algorithm)
	if alg != jose.ES256 && alg != jose.ES384 && alg != jose.ES512 {
		return nil, fmt.Errorf("algorithme JWK %q non accepté (ES256, ES384 ou ES512)", jwk.Algorithm)
	}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: &jwk}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return nil, err
	}
	// Une courbe qui ne correspond pas à l'algorithme ne se voit qu'à la signature: l'éprouver ici, pas en production.
	if _, err := s.Sign([]byte("sonde")); err != nil {
		return nil, errors.New("le JWK ne permet pas de signer avec l'algorithme déclaré")
	}
	return &roleSigner{provisioner: role.Provisioner, signer: s}, nil
}

// sign demande à step-ca un certificat puis le vérifie entièrement avant de le rendre.
func (c *caClient) sign(ctx context.Context, rs *roleSigner, v *validated) (*ssh.Certificate, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	now := c.now()
	opts := map[string]any{
		"certType": "user", "keyID": v.KeyID, "principals": []string{v.Principal}, "validBefore": v.TTL.String(),
	}
	tok, err := jwt.Signed(rs.signer).
		Claims(jwt.Claims{
			Issuer: rs.provisioner, Subject: v.KeyID, Audience: jwt.Audience{c.aud},
			IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now),
			Expiry: jwt.NewNumericDate(now.Add(tokenLifetime)), ID: hex.EncodeToString(id),
		}).
		Claims(map[string]any{"step": map[string]any{"ssh": opts}}).
		Serialize()
	if err != nil {
		return nil, err
	}
	reqBody := map[string]any{"publicKey": v.Key.Marshal(), "ott": tok}
	for k, val := range opts {
		reqBody[k] = val
	}
	var resp struct {
		Crt string `json:"crt"`
	}
	if err := c.call(ctx, http.MethodPost, "/1.0/ssh/sign", reqBody, &resp); err != nil {
		return nil, err
	}
	blob, err := base64.StdEncoding.DecodeString(resp.Crt)
	if err != nil {
		return nil, errors.New("certificat de la CA illisible")
	}
	pub, err := ssh.ParsePublicKey(blob)
	cert, ok := pub.(*ssh.Certificate)
	if err != nil || !ok {
		return nil, errors.New("la CA n'a pas renvoyé un certificat SSH")
	}
	if err := c.check(cert, v); err != nil {
		return nil, err
	}
	return cert, nil
}

// check est la dernière barrière: ce que la CA renvoie doit être exactement ce qui a été demandé, signé par la CA connue.
func (c *caClient) check(cert *ssh.Certificate, v *validated) error {
	now := c.now()
	switch {
	case cert.CertType != ssh.UserCert:
		return errors.New("certificat refusé: ce n'est pas un certificat utilisateur")
	case !bytes.Equal(cert.Key.Marshal(), v.Key.Marshal()):
		return errors.New("certificat refusé: la clé signée n'est pas celle demandée")
	case cert.KeyId != v.KeyID:
		return errors.New("certificat refusé: key id différent")
	case len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != v.Principal:
		return errors.New("certificat refusé: principals différents de la demande")
	case cert.ValidBefore == ssh.CertTimeInfinity:
		return errors.New("certificat refusé: sans expiration")
	case cert.ValidBefore > uint64(now.Add(v.TTL+certSkew).Unix()): // #nosec G115 -- l'instant visé est positif; comparaison faite en uint64 pour ne pas dépendre d'un débordement
		return errors.New("certificat refusé: validité plus longue que demandée")
	}
	if _, ok := cert.CriticalOptions["force-command"]; ok {
		return errors.New("certificat refusé: force-command")
	}
	// Seule permit-pty est attendue (modèle SSH du provisioner). Toute autre extension (forwarding de port, d'agent, X11, user-rc)
	// élargirait les droits de la session: refusée. shortcut: liste fixe dans le code, à passer en configuration si un rôle en a besoin.
	for ext := range cert.Extensions {
		if ext != "permit-pty" {
			return fmt.Errorf("certificat refusé: extension %q non prévue", ext)
		}
	}
	// CheckCert vérifie la signature mais pas QUI a signé: l'autorité doit être contrôlée à part.
	if !c.isUserCA(cert.SignatureKey) {
		return errors.New("certificat refusé: signé par une autorité inconnue")
	}
	chk := ssh.CertChecker{Clock: c.now}
	if err := chk.CheckCert(v.Principal, cert); err != nil {
		return fmt.Errorf("certificat refusé: %w", err)
	}
	return nil
}

func (c *caClient) isUserCA(k ssh.PublicKey) bool {
	for _, ca := range c.userCAs {
		if bytes.Equal(k.Marshal(), ca.Marshal()) {
			return true
		}
	}
	return false
}
