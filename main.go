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
	"log"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"time"
)

func runEnvoy(ctx context.Context) {
	//cmd := exec.CommandContext(ctx, "envoy", "-c", "envoy.yaml", "-l", "trace")
	cmd := exec.CommandContext(ctx, "/home/jrockway/tmp/envoy/bazel-bin/source/exe/envoy-static", "-c", "envoy.yaml", "--component-log-level", "file:debug")
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

func generateCert(dir, name string) (*certs, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
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
			Organization: []string{name},
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
	certOut, err := os.Create(filepath.Join(dir, "tls.crt"))
	if err != nil {
		return nil, err
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, err
	}
	if err := certOut.Close(); err != nil {
		return nil, err
	}

	keyOut, err := os.OpenFile(filepath.Join(dir, "tls.key"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
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
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	cfg := &tls.Config{
		RootCAs: pool,
	}
	return &certs{tlsConfig: cfg, dir: dir}, nil
}

func atomicLink(tmpdir, dir string) error {
	if err := os.Symlink(dir, filepath.Join(tmpdir, "..tmp")); err != nil {
		return err
	}
	if err := os.Rename(filepath.Join(tmpdir, "..tmp"), filepath.Join(tmpdir, "..data")); err != nil {
		return err
	}
	return nil
}

func printTree(tmpdir string) {
	cmd := exec.Command("ls", "-la", "certs")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
	cmd = exec.Command("ls", "-laR", tmpdir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
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

func run() error {
	ctx, c := context.WithCancel(context.Background())
	defer c()
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

	tmpdir := "/tmp/certs"
	cleanupTmp := func() {
		log.Printf("removing tmpdir %s", tmpdir)
		if err := os.RemoveAll(tmpdir); err != nil {
			log.Printf("failed to clean up tmpdir %s: %v", tmpdir, err)
		}
	}
	cleanupTmp()
	if err := os.MkdirAll(tmpdir, 0o755); err != nil {
		return err
	}
	defer cleanupTmp()
	if err := os.Symlink("..data/tls.crt", filepath.Join(tmpdir, "tls.crt")); err != nil {
		return err
	}
	if err := os.Symlink("..data/tls.key", filepath.Join(tmpdir, "tls.key")); err != nil {
		return err
	}

	certs, err := generateCert(filepath.Join(tmpdir, "..a"), "a")
	if err != nil {
		return fmt.Errorf("failed to write certs: %w", err)
	}
	if err := atomicLink(tmpdir, "..a"); err != nil {
		return err
	}

	go runEnvoy(ctx)
	time.Sleep(time.Second)
	printTree(tmpdir)

	if err := get(ctx, certs.tlsConfig); err != nil {
		return fmt.Errorf("failed to make initial request: %w", err)
	}

	newCerts, err := generateCert(filepath.Join(tmpdir, "..b"), "b")
	if err != nil {
		return fmt.Errorf("failed to write new certs: %w", err)
	}
	if err := atomicLink(tmpdir, "..b"); err != nil {
		return err
	}

	printTree(tmpdir)
	log.Println("sleeping")
	time.Sleep(5 * time.Second)

	if err := get(ctx, newCerts.tlsConfig); err != nil {
		return fmt.Errorf("failed to make request after cert rotation: %w", err)
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
