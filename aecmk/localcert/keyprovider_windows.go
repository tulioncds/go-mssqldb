//go:build !go1.17

package localcert

import (
	"crypto/x509"
	"fmt"
)

func (p *LocalCertProvider) loadWindowsCertStoreCertificate(path string) (privateKey interface{}, cert *x509.Certificate) {
	panic(fmt.Errorf("Windows cert store not supported until Go 1.17"))
	return
}
