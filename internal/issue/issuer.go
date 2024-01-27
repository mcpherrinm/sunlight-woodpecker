// Package issue contains code to issue certificates for testing in CT
// It contains code from github.com/letsencrypt/boulder and github.com/jsha/minica
package issue

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math"
	"math/big"
	"time"

	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
)

type Issuer struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func generateSCTListExt(scts []*ct.SignedCertificateTimestamp) (pkix.Extension, error) {
	list := ctx509.SignedCertificateTimestampList{}
	for _, sct := range scts {
		sctBytes, err := cttls.Marshal(*sct)
		if err != nil {
			return pkix.Extension{}, err
		}
		list.SCTList = append(list.SCTList, ctx509.SerializedSCT{Val: sctBytes})
	}
	listBytes, err := cttls.Marshal(list)
	if err != nil {
		return pkix.Extension{}, err
	}
	extBytes, err := asn1.Marshal(listBytes)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2},
		Value: extBytes,
	}, nil
}

func (i *Issuer) GetPrecert(sans []string) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		DNSNames:              sans,
		SerialNumber:          serial,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 3, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{{
			// OID for CT poison, RFC 6962 (was never assigned a proper id-pe- name)
			Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3},
			Value:    asn1.NullBytes,
			Critical: true,
		}},
	}

	// Because we never actually use these keys, we just make a new private key and throw it away.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return x509.CreateCertificate(rand.Reader, template, i.cert, key.Public(), i.key)
}

func (i *Issuer) GetCertForPrecert(asn1cert []byte, scts []*ct.SignedCertificateTimestamp) ([]byte, error) {
	cert, err := x509.ParseCertificate(asn1cert)
	if err != nil {
		return nil, err
	}

	ext, err := generateSCTListExt(scts)
	if err != nil {
		return nil, err
	}
	cert.ExtraExtensions = append(cert.ExtraExtensions, ext)

	return x509.CreateCertificate(rand.Reader, cert, i.cert, cert.PublicKey, i.key)
}

func New(certFile, keyFile string) (*Issuer, error) {
	cert, err := loadCert(certFile)
	if err != nil {
		return nil, fmt.Errorf("reading cert %s: %w", certFile, err)
	}

	key, err := loadKey(keyFile)
	if err != nil {
		return nil, fmt.Errorf("reading key %s: %w", keyFile, err)
	}

	return &Issuer{cert: cert, key: key}, nil
}
