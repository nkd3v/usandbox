// tlsprobe is a test aid for usandbox's TLS key extraction and transparent capture.
//
//	tlsprobe server -addr 0.0.0.0:8443 -cert server.pem
//	    a TLS server (self-signed certificate written to -cert) answering HTTP/1.1 and HTTP/2
//	tlsprobe client -url https://192.168.1.5:8443/x -pin server.pem [-tls 1.2|1.3] [-cipher aes128|aes256|chacha] [-h2] [-n 3] [-proxy env|none]
//	    a client that trusts only the pinned certificate (so interception fails, as with a
//	    pinning program), sends -n POST requests on one connection and prints the answers
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: tlsprobe server|client [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "server":
		server(os.Args[2:])
	case "client":
		client(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "usage: tlsprobe server|client [flags]")
		os.Exit(2)
	}
}

func server(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	addr := fs.String("addr", "0.0.0.0:8443", "listen address")
	certFile := fs.String("cert", "server.pem", "where to write the self-signed certificate")
	fs.Parse(args)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "tlsprobe"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "tlsprobe.test"},
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ipn.IP)
			}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	os.WriteFile(*certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "tlsprobe answer to %s %s over %s (%s): got %q\n", r.Method, r.URL.Path, r.Proto, tlsName(r.TLS), body)
	})
	srv := &http.Server{Addr: *addr, Handler: mux, TLSConfig: &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{ // TLS 1.2 only; Go chooses TLS 1.3 suites itself
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}}
	fmt.Printf("listening on %s, certificate in %s\n", *addr, *certFile)
	panic(srv.ListenAndServeTLS("", ""))
}

func tlsName(s *tls.ConnectionState) string {
	if s == nil {
		return "plain"
	}
	return fmt.Sprintf("%s %s", tls.VersionName(s.Version), tls.CipherSuiteName(s.CipherSuite))
}

func client(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	url := fs.String("url", "", "URL to POST to")
	pin := fs.String("pin", "", "PEM certificate to trust (only this one); empty = system roots")
	version := fs.String("tls", "1.3", "1.2 or 1.3")
	cipher := fs.String("cipher", "", "TLS 1.2 suite: aes128, aes256 or chacha")
	h2 := fs.Bool("h2", false, "allow HTTP/2")
	n := fs.Int("n", 2, "requests on one connection")
	proxy := fs.String("proxy", "env", "env (HTTPS_PROXY) or none")
	hold := fs.Duration("hold", 300*time.Millisecond, "pause between requests")
	keylog := fs.String("keylog", "", "write TLS secrets here (ground truth for tests)")
	rejectIssuer := fs.String("reject-issuer", "", "refuse certificates whose issuer contains this text (acts like pinning against an interceptor)")
	method := fs.String("method", "POST", "GET or POST")
	fs.Parse(args)

	cfg := &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13}
	if *version == "1.2" {
		cfg.MaxVersion = tls.VersionTLS12
	}
	switch *cipher {
	case "aes128":
		cfg.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
	case "aes256":
		cfg.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384}
	case "chacha":
		cfg.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256}
	}
	if *pin != "" {
		pemData, err := os.ReadFile(*pin)
		if err != nil {
			panic(err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pemData)
		cfg.RootCAs = pool
	}
	if *rejectIssuer != "" {
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			for _, c := range cs.PeerCertificates {
				if strings.Contains(strings.ToLower(c.Issuer.String()), strings.ToLower(*rejectIssuer)) {
					return fmt.Errorf("pinned: refusing certificate issued by %s", c.Issuer)
				}
			}
			return nil
		}
	}
	if *keylog != "" {
		f, _ := os.Create(*keylog)
		defer f.Close()
		cfg.KeyLogWriter = f
	}
	tr := &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: *h2, MaxIdleConnsPerHost: 1}
	if *proxy == "env" {
		tr.Proxy = http.ProxyFromEnvironment
	}
	if !*h2 {
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	c := &http.Client{Transport: tr, Timeout: 20 * time.Second}
	for i := 0; i < *n; i++ {
		var resp *http.Response
		var err error
		if *method == "GET" {
			resp, err = c.Get(*url)
		} else {
			resp, err = c.Post(*url, "application/json", bytes.NewBufferString(fmt.Sprintf(`{"probe":%d,"secret":"tlsprobe-%d"}`, i, i)))
		}
		if err != nil {
			fmt.Println("error:", err)
			os.Exit(1)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		fmt.Printf("%d %s %s", resp.StatusCode, resp.Proto, strings.TrimSpace(string(body))+"\n")
		time.Sleep(*hold)
	}
}
