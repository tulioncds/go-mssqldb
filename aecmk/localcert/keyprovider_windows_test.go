package localcert

import (
	"crypto/rsa"
	"strings"
	"testing"

	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/internal/certs"
)

func TestLoadWindowsCertStoreCertificate(t *testing.T) {
	thumbprint, err := certs.ProvisionMasterKeyInCertStore()
	if err != nil {
		t.Fatal(err)
	}
	defer certs.DeleteMasterKeyCert(thumbprint)
	provider := &LocalCertProvider{Name: mssql.AzureKeyVaultKeyProvider}
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
