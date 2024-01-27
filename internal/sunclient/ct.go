package sunclient

import (
	"context"
	"log"
	"net/http"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
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

	// TODO: This is where we load and verify the sunlight tiles

	return sct, err
}

func (l *Log) SubmitFinal(ctx context.Context, asn1cert []byte) error {
	_, err := l.ct.AddChain(ctx, []ct.ASN1Cert{{Data: asn1cert}})

	// TODO: This is where we load and verify the sunlight tiles

	return err
}
