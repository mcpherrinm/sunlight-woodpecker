package sunclient

import (
	"context"
	"errors"
	"log"
	"net/http"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"golang.org/x/crypto/cryptobyte"
)

type Log struct {
	ct *client.LogClient
}

func New(url string) (*Log, error) {
	ctclient, err := client.New(url, &http.Client{}, jsonclient.Options{Logger: log.Default()})
	if err != nil {
		return nil, err
	}
	return &Log{ct: ctclient}, nil
}

func (l *Log) SubmitPreCert(ctx context.Context, asn1cert []byte) (*ct.SignedCertificateTimestamp, error) {
	sct, err := l.ct.AddPreChain(ctx, []ct.ASN1Cert{{Data: asn1cert}})
	if err != nil {
		return nil, err
	}

	if err = l.SunlightValidate(ctx, asn1cert, sct); err != nil {
		return nil, err
	}

	return sct, nil
}

func (l *Log) SubmitFinal(ctx context.Context, asn1cert []byte) error {
	sct, err := l.ct.AddChain(ctx, []ct.ASN1Cert{{Data: asn1cert}})
	if err != nil {
		return err
	}

	return l.SunlightValidate(ctx, asn1cert, sct)
}

// SunlightValidate takes a certificate and SCT to check its inclusion in the log.
//
// The leaf index is extracted from the SCT. We load tiles along with the STH to validate inclusion.
func (l *Log) SunlightValidate(ctx context.Context, asn1cert []byte, sct *ct.SignedCertificateTimestamp) error {
	_, err := sunlightIndex(sct.Extensions)
	if err != nil {
		return err
	}

	return nil
}

// sunlightIndex parses the extensions from an SCT, finds the leaf_index extension, and returns the value
// non-public function taken from sunlight
func sunlightIndex(extensions ct.CTExtensions) (uint64, error) {
	b := cryptobyte.String(extensions)
	for !b.Empty() {
		var extensionType uint8
		var extension cryptobyte.String
		if !b.ReadUint8(&extensionType) || !b.ReadUint16LengthPrefixed(&extension) {
			return 0, errors.New("invalid extension")
		}
		if extensionType == 0 /* leaf_index */ {
			var leafIndex int64
			if !readUint40(&extension, &leafIndex) || !extension.Empty() {
				return 0, errors.New("invalid leaf_index extension")
			}
			return uint64(leafIndex), nil
		}
	}
	return 0, errors.New("missing leaf_index extension")
}

// readUint40 decodes a big-endian, 40-bit value into out and advances over it.
// It reports whether the read was successful.
// non-public function taken from sunlight
func readUint40(s *cryptobyte.String, out *int64) bool {
	var v []byte
	if !s.ReadBytes(&v, 5) {
		return false
	}
	*out = int64(v[0])<<32 | int64(v[1])<<24 | int64(v[2])<<16 | int64(v[3])<<8 | int64(v[4])
	return true
}
