package mssql

import (
	"fmt"
	"testing"

	"github.com/microsoft/go-mssqldb/internal/certs"
)

func TestAlwaysEncryptedE2E(t *testing.T) {
	params := testConnParams(t)
	if !params.ColumnEncryption {
		t.Skip("Test is not running with column encryption enabled")
	}
	conn, _ := open(t)
	defer conn.Close()
	thumbprint, err := certs.ProvisionMasterKeyInCertStore()
	if err != nil {
		t.Fatal(err)
	}
	defer certs.DeleteMasterKeyCert(thumbprint)
	certPath := fmt.Sprintf(`CurrentUser/My/%s`, thumbprint)
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
	createColumnMasterKey = `CREATE COLUMN MASTER KEY [%s] WITH (KEY_STORE_PROVIDER_NAME= 'MSSQL_CERTIFICATE_STORE', KEY_PATH='%s')`
	dropColumnMasterKey   = `DROP COLUMN MASTER KEY [%s]`
)
