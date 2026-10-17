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
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           newServer(cfg, ca, signers, log).routes(),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      40 * time.Second, // > signTimeout
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
		// HTTP/1.1 seulement: un client unique (Warpgate) n'a pas besoin de HTTP/2, et on retire cette surface d'attaque.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey) }()
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

// healthcheck interroge /healthz sur la boucle locale. La vérification du certificat est omise ici car on ne
// teste que la vivacité de son propre processus, sans rien envoyer de sensible.
func healthcheck(cfgPath string) error {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	_, port, _ := net.SplitHostPort(cfg.Listen)
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}, // #nosec G402 -- sonde locale
		},
	}
	resp, err := client.Get("https://" + net.JoinHostPort("127.0.0.1", port) + "/healthz") // #nosec G107 -- boucle locale
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz: statut %d", resp.StatusCode)
	}
	return nil
}
