package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// health checks /healthz over TCP and over HTTP/3, the way the container's
// health check and an operator's laptop run it:
//
//	ftwcloudd health -name cloud.ftw.energy https://127.0.0.1/healthz
//	ftwcloudd health https://cloud.ftw.energy/healthz
//
// Each line names the protocol that answered and how long it took. Either
// failing fails the check: a host whose UDP is shut while Alt-Svc says
// HTTP/3 is there makes every client race for nothing.
func health(args []string) error {
	fs := flag.NewFlagSet("health", flag.ExitOnError)
	name := fs.String("name", "", "the certificate's name, when the URL names an address")
	insecure := fs.Bool("insecure", false, "accept any certificate (local tests only)")
	h3 := fs.Bool("h3", true, "check HTTP/3 too")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: ftwcloudd health [-name host] [-h3=false] https://host/healthz")
	}
	u, err := url.Parse(fs.Arg(0))
	if err != nil || u.Scheme != "https" {
		return fmt.Errorf("health: %q is not an https URL", fs.Arg(0))
	}
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: *name, InsecureSkipVerify: *insecure}
	tcp := &http.Transport{TLSClientConfig: tlsConf.Clone(), DisableKeepAlives: true}
	defer tcp.CloseIdleConnections()
	clients := []*http.Client{{Transport: tcp}}
	if *h3 {
		quic := &http3.Transport{TLSClientConfig: tlsConf.Clone()}
		defer quic.Close()
		clients = append(clients, &http.Client{Transport: quic})
	}
	for _, c := range clients {
		c.Timeout = 5 * time.Second
		start := time.Now()
		proto, err := get(c, u.String())
		if err != nil {
			return err
		}
		fmt.Printf("%s ok in %d ms\n", proto, time.Since(start).Milliseconds())
	}
	return nil
}

func get(c *http.Client, u string) (string, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	if resp.StatusCode != http.StatusOK || string(body) != "ok\n" {
		return resp.Proto, fmt.Errorf("health: %s answered %d", resp.Proto, resp.StatusCode)
	}
	return resp.Proto, nil
}
