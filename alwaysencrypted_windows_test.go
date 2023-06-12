package mssql

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/Microsoft/go-winio/pkg/guid"
)

func TestAlwaysEncryptedE2E(t *testing.T) {
	params := testConnParams(t)
	if !params.ColumnEncryption {
		t.Skip("Test is not running with column encryption enabled")
	}
	conn, _ := open(t)
	defer conn.Close()
	certPath := provisionMasterKeyInCertStore(t)
	s := fmt.Sprintf(createColumnMasterKey, certPath, certPath)
	if _, err := conn.Exec(s); err != nil {
		t.Fatalf("Unable to create CMK: %s", err.Error())
	}
	defer conn.Exec(fmt.Sprintf(dropColumnMasterKey, certPath))
	// TODO: Implement encryption and insert encrypted values into a table using custom CEK
	rows, err := conn.Query("select top (1) col1, col2 from Table_1")
	if err != nil {
		t.Fatalf("Unable to query encrypted columns: %s", err.Error())
	}
	if !rows.Next() {
		rows.Close()
		t.Fatalf("rows.Next returned false")
	}
	var col1 string
	var col2 int32
	err = rows.Scan(&col1, &col2)
	if err != nil {
		rows.Close()
		t.Fatalf("rows.Scan failed: %s", err.Error())
	}
	rows.Close()
	err = rows.Err()
	if err != nil {
		t.Fatalf("rows.Err() has non-nil value: %s", err.Error())
	}
}

const (
	createUserCertScript  = `New-SelfSignedCertificate -Subject "%s" -CertStoreLocation Cert:CurrentUser\My -KeyExportPolicy Exportable -Type DocumentEncryptionCert -KeyUsage KeyEncipherment -Keyspec KeyExchange -KeyLength 2048 | select {$_.Thumbprint}`
	deleteUserCertScript  = `Get-ChildItem Cert:\CurrentUser\My\%s | Remove-Item -DeleteKey`
	createColumnMasterKey = `CREATE COLUMN MASTER KEY [%s] WITH (KEY_STORE_PROVIDER_NAME= 'MSSQL_CERTIFICATE_STORE', KEY_PATH='%s')`
	dropColumnMasterKey   = `DROP COLUMN MASTER KEY [%s]`
)

func provisionMasterKeyInCertStore(t *testing.T) string {
	t.Helper()
	var g guid.GUID
	var err error
	if g, err = guid.NewV4(); err != nil {
		t.Fatalf("Unable to allocate a guid %v", err.Error())
	}
	subject := fmt.Sprintf(`gomssqltest-%s`, g.String())

	cmd := exec.Command(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `/ExecutionPolicy`, `Unrestricted`, fmt.Sprintf(createUserCertScript, subject))
	buf := &memoryBuffer{buf: new(bytes.Buffer)}
	cmd.Stdout = buf
	if err = cmd.Run(); err != nil {
		t.Fatalf("Unable to create cert for encryption: %v", err.Error())
	}
	out := buf.buf.String()
	thumbPrint := strings.Trim(out[strings.LastIndex(out, "-"):], "\r\n")
	return fmt.Sprintf(`CurrentUser/My/%s`, thumbPrint)
}

func deleteMasterKeyCert(t *testing.T, thumbprint string) {
	t.Helper()
	cmd := exec.Command(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `/ExecutionPolicy`, `Unrestricted`, fmt.Sprintf(deleteUserCertScript, thumbprint))
	if err := cmd.Run; err != nil {
		t.Fatalf("Unable to delete user cert %s", thumbprint)
	}
}

type memoryBuffer struct {
	buf *bytes.Buffer
}

func (b *memoryBuffer) Write(p []byte) (n int, err error) {
	return b.buf.Write(p)
}

func (b *memoryBuffer) Close() error {
	return nil
}

// C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe /ExecutionPolicy Unrestricted New-SelfSignedCertificate -Subject "%s" -CertStoreLocation Cert:CurrentUser\My -KeyExportPolicy Exportable -Type DocumentEncryptionCert -KeyUsage KeyEncipherment -Keyspec KeyExchange -KeyLength 2048 | select {$_.Thumbprint}
