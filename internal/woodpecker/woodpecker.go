package woodpecker

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	ct "github.com/google/certificate-transparency-go"
)

type Issuer interface {
	// GetPrecert issues a cert for the specified SANs
	GetPrecert(sans []string) ([]byte, error)

	// GetCertForPrecert gets the cert for a precert with this SCT embedded in it
	GetCertForPrecert(cert []byte, scts []*ct.SignedCertificateTimestamp) ([]byte, error)
}

type Log interface {
	SubmitPreCert(ctx context.Context, cert []byte) (*ct.SignedCertificateTimestamp, error)
	SubmitFinal(ctx context.Context, cert []byte) error
}

type Woodpecker struct {
	basedomain string
	issuer     Issuer
	log        Log
}

func New(basedomain string, issuer Issuer, log Log) (*Woodpecker, error) {
	return &Woodpecker{
		basedomain: basedomain,
		issuer:     issuer,
		log:        log,
	}, nil
}

func randDomains(baseDomain string) []string {
	var domains []string
	domainCount := rand.Intn(100) + 1
	for i := 0; i < domainCount; i++ {
		domains = append(domains, fmt.Sprintf("r%dz%x.%s", time.Now().Unix(), rand.Int(), baseDomain))
	}
	return domains
}

func (wp *Woodpecker) Peck(ctx context.Context, iterations int) error {
	for i := 0; i < iterations; i++ {
		precert, err := wp.issuer.GetPrecert(randDomains(wp.basedomain))
		if err != nil {
			return err
		}

		sct, err := wp.log.SubmitPreCert(ctx, precert)
		if err != nil {
			return err
		}

		finalCert, err := wp.issuer.GetCertForPrecert(precert, []*ct.SignedCertificateTimestamp{sct})
		if err != nil {
			return err
		}

		err = wp.log.SubmitFinal(ctx, finalCert)
		if err != nil {
			return err
		}
	}

	return nil
}
