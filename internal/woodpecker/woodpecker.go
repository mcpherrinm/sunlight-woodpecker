package woodpecker

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"log/slog"
	"math/rand"
	"net/http"
	"time"

	"filippo.io/sunlight"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	cttls "github.com/google/certificate-transparency-go/tls"
	"github.com/mcpherrinm/sunlight-woodpecker/config"
	"golang.org/x/mod/sumdb/tlog"
)

type Issuer interface {
	// GetPrecert issues a cert for the specified SANs
	GetPrecert(sans []string) ([]ct.ASN1Cert, error)

	// GetCertForPrecert gets the cert for a precert with this SCT embedded in it
	GetCertForPrecert(cert []ct.ASN1Cert, scts []*ct.SignedCertificateTimestamp) ([]ct.ASN1Cert, error)
}

type Woodpecker struct {
	basedomain string
	issuer     Issuer
	ct         *client.LogClient
	sunlight   *sunlight.Client
}

func New(basedomain string, issuer Issuer, cfg config.Log) (*Woodpecker, error) {
	derPubKey, err := base64.StdEncoding.DecodeString(cfg.PublicKey)
	if err != nil {
		return nil, err
	}

	options := jsonclient.Options{Logger: log.Default(), PublicKeyDER: derPubKey}
	key, err := options.ParsePublicKey()
	if err != nil {
		return nil, err
	}

	ctClient, err := client.New(cfg.URL, &http.Client{}, options)
	if err != nil {
		return nil, err
	}

	scClient, err := sunlight.NewClient(&sunlight.ClientConfig{
		MonitoringPrefix: cfg.Monitoring,
		PublicKey:        key,
		HTTPClient:       nil, // Uses a default client
		UserAgent:        "sunlight-woodpecker/1.0 (+https://github.com/mcpherrinm/sunlight-woodpecker)",
		Timeout:          0,  // Default 5 minute timeout
		ConcurrencyLimit: 0,  // no Limit
		Cache:            "", // No tile cache
		Logger:           slog.Default(),
	})
	if err != nil {
		return nil, err
	}

	return &Woodpecker{
		basedomain: basedomain,
		issuer:     issuer,
		ct:         ctClient,
		sunlight:   scClient,
	}, nil
}

func randDomains(baseDomain string) []string {
	var domains []string
	domainCount := rand.Intn(100) + 1
	for range domainCount {
		domains = append(domains, fmt.Sprintf("r%dz%x.%s", time.Now().Unix(), rand.Int(), baseDomain))
	}
	return domains
}

// Peck is the main woodpecker operation:
// Create a precert with
func (wp *Woodpecker) Peck(ctx context.Context) error {
	precert, err := wp.issuer.GetPrecert(randDomains(wp.basedomain))
	if err != nil {
		return err
	}

	sct, err := wp.ct.AddPreChain(ctx, precert)
	if err != nil {
		return err
	}

	finalCert, err := wp.issuer.GetCertForPrecert(precert, []*ct.SignedCertificateTimestamp{sct})
	if err != nil {
		return err
	}

	finalSCT, err := wp.ct.AddChain(ctx, finalCert)
	if err != nil {
		return err
	}

	checkpoint, _, err := wp.sunlight.Checkpoint(ctx)
	if err != nil {
		return err
	}

	err = wp.CheckInclusion(ctx, checkpoint.Tree, sct)
	if err != nil {
		return err
	}

	err = wp.CheckInclusion(ctx, checkpoint.Tree, finalSCT)
	if err != nil {
		return err
	}

	return nil
}

// CheckInclusion is a wrapper around sunlight's CheckInclusion which converts the SCT type.
func (wp *Woodpecker) CheckInclusion(ctx context.Context, tree tlog.Tree, sct *ct.SignedCertificateTimestamp) error {
	sctBytes, err := cttls.Marshal(*sct)
	if err != nil {
		return err
	}

	_, _, err = wp.sunlight.CheckInclusion(ctx, tree, sctBytes)
	return err
}
