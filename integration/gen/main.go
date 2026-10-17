// Commande de test: génère les secrets jetables de l'environnement d'intégration (provisioner JWK, TLS, jeton, configuration).
// Rien ici ne sert en production. Usage: gen <répertoire de sortie>
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const template = `{
	"type": "user",
	"keyId": {{ toJson .KeyID }},
	"principals": ["ops"],
	"extensions": {"permit-pty": ""}
}
`

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	_, err := rand.Read(b)
	must(err)
	return hex.EncodeToString(b)
}

func write(dir, name string, data []byte, mode os.FileMode) {
	must(os.WriteFile(filepath.Join(dir, name), data, mode))
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: gen <répertoire>")
		os.Exit(2)
	}
	dir := os.Args[1]

	// Provisioner JWK (ES256), clé privée chiffrée comme dans ca.json.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	jwk := jose.JSONWebKey{Key: priv, Algorithm: "ES256", Use: "sig"}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	must(err)
	jwk.KeyID = base64.RawURLEncoding.EncodeToString(tp)
	plain, err := json.Marshal(jwk)
	must(err)
	pw := randHex(16)
	enc, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.PBES2_HS256_A128KW, Key: []byte(pw), PBES2Count: 10000}, nil)
	must(err)
	obj, err := enc.Encrypt(plain)
	must(err)
	jwe, err := obj.CompactSerialize()
	must(err)
	pub, err := json.Marshal(jwk.Public())
	must(err)
	prov, err := json.Marshal(map[string]any{
		"type": "JWK", "name": "warpgate-ops", "key": json.RawMessage(pub), "encryptedKey": jwe,
		"claims":  map[string]any{"enableSSHCA": true, "minUserSSHCertDuration": "1m", "defaultUserSSHCertDuration": "5m", "maxUserSSHCertDuration": "10m"},
		"options": map[string]any{"ssh": map[string]any{"templateFile": "templates/ssh/warpgate-ops.tpl"}},
	})
	must(err)
	write(dir, "provisioner.json", prov, 0o600)
	write(dir, "jwk.jwe", []byte(jwe), 0o600)
	write(dir, "jwk.pw", []byte(pw), 0o600)
	write(dir, "warpgate-ops.tpl", []byte(template), 0o600)

	// Certificat TLS de l'adaptateur (auto-signé, valable un jour).
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "adapter"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true, DNSNames: []string{"adapter"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	must(err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(k)
	must(err)
	write(dir, "tls.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	write(dir, "tls.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)

	// Jeton d'API de Warpgate (seule son empreinte va dans la configuration).
	token := "s." + randHex(32)
	sum := sha256.Sum256([]byte(token))
	write(dir, "token", []byte(token), 0o600)
	// #nosec G101 -- noms de champs de configuration (chemins de fichiers), aucun secret en dur
	cfg, err := json.MarshalIndent(map[string]any{
		"listen": ":8200", "tls_cert": "/etc/adapter/tls.crt", "tls_key": "/etc/adapter/tls.key", "mount": "ssh",
		"ca":     map[string]any{"url": "https://it-stepca:9000", "root_file": "/etc/adapter/root_ca.crt"},
		"tokens": []any{map[string]any{"name": "warpgate", "sha256": hex.EncodeToString(sum[:]), "roles": []string{"ops"}}},
		"roles": map[string]any{"ops": map[string]any{
			"provisioner": "warpgate-ops", "key_file": "/etc/adapter/jwk.jwe", "password_file": "/etc/adapter/jwk.pw",
			"principals": []string{"ops"}, "max_ttl": "10m",
		}},
	}, "", "  ")
	must(err)
	write(dir, "config.json", cfg, 0o600)
}
