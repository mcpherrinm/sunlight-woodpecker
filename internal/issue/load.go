package issue

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func loadCert(certFile string) (*x509.Certificate, error) {
	certContent, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	block, _ := pem.Decode(certContent)
	if block == nil {
		return nil, fmt.Errorf("no PEM content")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("wrong PEM type: %s", block.Type)
	}

	return x509.ParseCertificate(block.Bytes)
}

func loadKey(keyFile string) (crypto.Signer, error) {
	keyContent, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}
	block, _ := pem.Decode(keyContent)
	if block == nil {
		return nil, fmt.Errorf("no PEM found")
	} else if block.Type == "PRIVATE KEY" {
		signer, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8: %w", err)
		}
		switch t := signer.(type) {
		case *rsa.PrivateKey:
			return signer.(*rsa.PrivateKey), nil
		case *ecdsa.PrivateKey:
			return signer.(*ecdsa.PrivateKey), nil
		default:
			return nil, fmt.Errorf("unsupported PKCS8 key type: %t", t)
		}
	} else if block.Type == "RSA PRIVATE KEY" {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	} else if block.Type == "EC PRIVATE KEY" || block.Type == "ECDSA PRIVATE KEY" {
		return x509.ParseECPrivateKey(block.Bytes)
	}
	return nil, fmt.Errorf("incorrect PEM type %s", block.Type)
}
