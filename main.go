// Commande warpgate-stepca-adapter: émule l'API de signature SSH de Vault devant step-ca.
// Spécification et menaces: voir README.md et security/threat-model.md.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

func main() {
	cfgPath := flag.String("config", "/etc/warpgate-stepca-adapter/config.json", "fichier de configuration JSON")
	health := flag.Bool("healthcheck", false, "sonde locale pour HEALTHCHECK du conteneur (code de sortie 0 si le service répond)")
	flag.Parse()
	if *health {
		if err := healthcheck(*cfgPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *cfgPath, log); err != nil {
		log.Error("arrêt sur erreur", "event", "fatal", "err", err.Error())
		os.Exit(1)
	}
}

// run démarre le service et ne rend la main qu'à l'arrêt. Toute anomalie au démarrage est fatale (fail closed).
func run(ctx context.Context, cfgPath string, log *slog.Logger) error {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	ca, err := newCAClient(ctx, cfg.CA)
	if err != nil {
		return err
	}
	signers := map[string]*roleSigner{}
	for name, r := range cfg.Roles {
		if signers[name], err = loadRoleSigner(r); err != nil {
			return fmt.Errorf("rôle %q: %w", name, err)
		}
	}
	certs, err := newCertReloader(cfg.TLSCert, cfg.TLSKey, log)
	if err != nil {
		return fmt.Errorf("certificat TLS: %w", err)
	}
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           newServer(cfg, ca, signers, log).routes(),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: certs.get},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      40 * time.Second, // > signTimeout
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
		// HTTP/1.1 seulement: un client unique (Warpgate) n'a pas besoin de HTTP/2, et on retire cette surface d'attaque.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ServeTLS(newLimitedListener(ln, cfg.MaxConns, cfg.MaxConnsPerIP, log), "", "") }()
	log.Info("démarré", "event", "start", "listen", cfg.Listen, "ca", cfg.CA.URL, "roles", len(cfg.Roles), "tokens", len(cfg.Tokens))
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdown); err != nil {
		return err
	}
	if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// healthURL vise l'adresse d'écoute réelle: la boucle locale seulement si le service écoute sur toutes les interfaces.
func healthURL(listen string) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", err
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return "https://" + net.JoinHostPort(host, port) + "/healthz", nil
}

// healthcheck interroge /healthz de son propre service. La vérification du certificat est omise ici car on ne
// teste que la vivacité de son propre processus, sans rien envoyer de sensible.
func healthcheck(cfgPath string) error {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	url, err := healthURL(cfg.Listen)
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}, // #nosec G402 -- sonde locale
		},
	}
	resp, err := client.Get(url) // #nosec G107 G704 -- adresse d'écoute de sa propre configuration
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz: statut %d", resp.StatusCode)
	}
	return nil
}

// certReloader sert le certificat TLS en le relisant quand les fichiers changent (renouvellement Let's Encrypt par exemple),
// sans redémarrage. Un nouveau fichier illisible ou incohérent est journalisé et l'ancien certificat reste servi.
type certReloader struct {
	certFile, keyFile string
	log               *slog.Logger
	mu                sync.Mutex
	cur               *tls.Certificate
	certMod, keyMod   time.Time
}

func newCertReloader(certFile, keyFile string, log *slog.Logger) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile, log: log}
	if _, err := r.get(nil); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	sc, errC := os.Stat(r.certFile)
	sk, errK := os.Stat(r.keyFile)
	if errC == nil && errK == nil && (r.cur == nil || !sc.ModTime().Equal(r.certMod) || !sk.ModTime().Equal(r.keyMod)) {
		r.certMod, r.keyMod = sc.ModTime(), sk.ModTime() // une seule tentative par changement de fichier
		c, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
		switch {
		case err == nil:
			r.cur = &c
			r.log.Info("certificat TLS chargé", "event", "tls_reload")
		case r.cur == nil:
			return nil, err
		default:
			r.log.Error("nouveau certificat TLS refusé, l'ancien reste servi", "event", "tls_reload_failed", "err", err.Error())
		}
	}
	if r.cur == nil {
		return nil, errors.New("aucun certificat TLS chargé")
	}
	return r.cur, nil
}
