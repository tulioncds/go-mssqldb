package localcert

import (
	"crypto/x509"
	"fmt"
)

func (p *LocalCertProvider) loadWindowsCertStoreCertificate(path string) (privateKey interface{}, cert *x509.Certificate) {
	panic(fmt.Errorf("Windows cert store not supported on this OS"))
	return
}