package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"time"
)

func runEnvoy(ctx context.Context) {
	cmd := exec.CommandContext(ctx, "envoy", "-c", "envoy.yaml", "-l", "critical")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Start(); err != nil {
		log.Fatalf("create envoy cmd: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		var done bool
		select {
		case <-ctx.Done():
			done = true
		default:
		}
		if !done {
			log.Fatalf("envoy exited early: %v", err)
		}
	}
}

type certs struct {
	tlsConfig *tls.Config
	dir       string
}

func generateCert() (*certs, error) {
	tmpdir, err := ioutil.TempDir("", "certs-")
	if err != nil {
		return nil, err
	}
	// This code is from https://golang.org/src/crypto/tls/generate_cert.go
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(5 * time.Minute)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 25)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		return nil, err
	}
	certOut, err := os.Create(tmpdir + "/tls.crt")
	if err != nil {
		return nil, err
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, err
	}
	if err := certOut.Close(); err != nil {
		return nil, err
	}

	keyOut, err := os.OpenFile(tmpdir+"/tls.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return nil, err
	}
	if err := keyOut.Close(); err != nil {
		return nil, err
	}
	if err := os.Symlink(tmpdir, "certs.tmp"); err != nil {
		return nil, err
	}
	if err := os.Rename("certs.tmp", "certs"); err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	cfg := &tls.Config{
		RootCAs: pool,
	}
	return &certs{tlsConfig: cfg, dir: tmpdir}, nil
}

func get(ctx context.Context, cfg *tls.Config) error {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: cfg,
		},
	}
	for i := 0; i < 10; i++ {
		req, err := http.NewRequest("GET", "https://localhost:10000/", nil)
		if err != nil {
			return fmt.Errorf("generate request: %w", err)
		}
		req = req.WithContext(ctx)
		res, err := client.Do(req)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			log.Printf("error: %v", err)
			time.Sleep(time.Second)
			continue
		} else if res.StatusCode != http.StatusOK {
			log.Printf("bad response: %s", res.Status)
			time.Sleep(time.Second)
			continue
		}
		log.Printf("got acceptable response: %s", res.Status)
		return nil
	}
	return errors.New("never received an acceptable response")
}

func main() {
	ctx, c := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		defer signal.Stop(sigCh)
		select {
		case <-ctx.Done():
			return
		case <-sigCh:
			log.Printf("interrupted")
			c()
		}
	}()

	certs, err := generateCert()
	if err != nil {
		log.Fatalf("failed to write certs: %v", err)
	}
	go runEnvoy(ctx)
	if err := get(ctx, certs.tlsConfig); err != nil {
		log.Printf("failed to make initial request: %v", err)
	}
	newCerts, err := generateCert()
	if err != nil {
		log.Printf("failed to write new certs: %v", err)
	}
	if err := get(ctx, newCerts.tlsConfig); err != nil {
		log.Printf("failed to make request after cert rotation: %v", err)
	}
	c()
	if err := os.RemoveAll(certs.dir); err != nil {
		log.Printf("failed to clean up tmpdir %s: %v", certs.dir, err)
	}
	if err := os.RemoveAll(newCerts.dir); err != nil {
		log.Printf("failed to clean up tmpdir %s: %v", certs.dir, err)
	}
}
