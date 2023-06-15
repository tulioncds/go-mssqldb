package localcert

import (
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/microsoft/go-mssqldb/aecmk"
	"github.com/microsoft/go-mssqldb/internal/certs"
)

func TestLoadWindowsCertStoreCertificate(t *testing.T) {
	thumbprint, err := certs.ProvisionMasterKeyInCertStore()
	if err != nil {
		t.Fatal(err)
	}
	defer certs.DeleteMasterKeyCert(thumbprint)
	provider := aecmk.GetGlobalCekProviders()[aecmk.CertificateStoreKeyProvider].Provider.(*LocalCertProvider)
	pk, cert := provider.loadWindowsCertStoreCertificate("CurrentUser/My/" + thumbprint)
	switch z := pk.(type) {
	case *rsa.PrivateKey:

		t.Logf("Got an rsa.PrivateKey with size %d", z.Size())
	default:
		t.Fatalf("Unexpected private key type: %v", z)
	}
	if !strings.HasPrefix(cert.Subject.String(), `CN=gomssqltest-`) {
		t.Fatalf("Wrong cert loaded: %s", cert.Subject.String())
	}
}
