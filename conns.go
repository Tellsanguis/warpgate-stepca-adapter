package main

import (
	"log/slog"
	"net"
	"sync"
	"time"
)

// limitedListener refuse (fermeture immédiate) les connexions au-delà d'un total et d'un plafond par IP source:
// un client lent ou malveillant ne peut pas occuper toutes les places. Les connexions déjà établies ne sont jamais coupées.
type limitedListener struct {
	net.Listener
	max, maxPerIP int
	log           *slog.Logger
	logLimit      *limiter // au plus quelques lignes de journal par minute, même sous inondation
	now           func() time.Time
	mu            sync.Mutex
	total         int
	perIP         map[string]int
}

func newLimitedListener(l net.Listener, max, maxPerIP int, log *slog.Logger) *limitedListener {
	return &limitedListener{Listener: l, max: max, maxPerIP: maxPerIP, log: log, logLimit: &limiter{max: 5}, now: time.Now, perIP: map[string]int{}}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		l.mu.Lock()
		ok := l.total < l.max && l.perIP[ip] < l.maxPerIP
		if ok {
			l.total++
			l.perIP[ip]++
		}
		l.mu.Unlock()
		if ok {
			return &trackedConn{Conn: c, l: l, ip: ip}, nil
		}
		_ = c.Close()
		if l.logLimit.allow(l.now()) {
			l.log.Warn("connexion refusée: trop de connexions simultanées", "event", "conn_limit", "remote", ip)
		}
	}
}

type trackedConn struct {
	net.Conn
	l    *limitedListener
	ip   string
	once sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		c.l.mu.Lock()
		c.l.total--
		if c.l.perIP[c.ip]--; c.l.perIP[c.ip] <= 0 {
			delete(c.l.perIP, c.ip)
		}
		c.l.mu.Unlock()
	})
	return c.Conn.Close()
}
