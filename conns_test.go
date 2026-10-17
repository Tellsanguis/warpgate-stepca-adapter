package main

import (
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

// listen démarre un listener limité et remet les connexions acceptées sur un canal.
func listen(t *testing.T, max, perIP int) (addr string, accepted chan net.Conn, ll *limitedListener) {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ll = newLimitedListener(raw, max, perIP, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	accepted = make(chan net.Conn, 16)
	go func() {
		for {
			c, err := ll.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	t.Cleanup(func() { _ = ll.Close() })
	return raw.Addr().String(), accepted, ll
}

// dial ouvre une connexion depuis l'adresse source donnée (127.0.0.x) et dit si le serveur l'a refusée (fermée tout de suite).
func dial(t *testing.T, addr, from string) (net.Conn, bool) {
	t.Helper()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(from)}, Timeout: 2 * time.Second}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, err = c.Read(make([]byte, 1))
	return c, err == io.EOF || (err != nil && strings.Contains(err.Error(), "reset"))
}

func next(t *testing.T, ch chan net.Conn) net.Conn {
	t.Helper()
	select {
	case c := <-ch:
		return c
	case <-time.After(2 * time.Second):
		t.Fatal("connexion attendue non acceptée")
		return nil
	}
}

func TestListenerPerIPLimit(t *testing.T) {
	addr, acc, ll := listen(t, 10, 2)
	for i := 0; i < 2; i++ {
		if _, refused := dial(t, addr, "127.0.0.1"); refused {
			t.Fatalf("connexion %d refusée sous le plafond", i+1)
		}
	}
	first := next(t, acc)
	next(t, acc)
	if _, refused := dial(t, addr, "127.0.0.1"); !refused {
		t.Fatal("la troisième connexion de la même IP aurait dû être refusée")
	}
	// Une autre IP source n'est pas affectée par le plafond de la première.
	if _, refused := dial(t, addr, "127.0.0.2"); refused {
		t.Fatal("une autre IP est refusée à cause de la première")
	}
	next(t, acc)
	// Fermer une connexion libère sa place, et une double fermeture ne compte pas deux fois.
	_ = first.Close()
	_ = first.Close()
	if _, refused := dial(t, addr, "127.0.0.1"); refused {
		t.Fatal("la place libérée n'est pas réutilisable")
	}
	ll.mu.Lock()
	total, ips := ll.total, len(ll.perIP)
	ll.mu.Unlock()
	if total != 3 || ips != 2 {
		t.Fatalf("comptes incohérents: total=%d ips=%d (attendu 3 et 2)", total, ips)
	}
}

func TestListenerGlobalLimit(t *testing.T) {
	addr, acc, _ := listen(t, 2, 10)
	dial(t, addr, "127.0.0.1")
	dial(t, addr, "127.0.0.2")
	next(t, acc)
	next(t, acc)
	if _, refused := dial(t, addr, "127.0.0.3"); !refused {
		t.Fatal("le plafond global n'est pas appliqué")
	}
}
