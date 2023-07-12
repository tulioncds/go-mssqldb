package mssql

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/microsoft/go-mssqldb/aecmk/localcert"
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
	r, _ := rand.Int(rand.Reader, big.NewInt(1000))
	cekName := fmt.Sprintf("mssqlCek%d", r.Int64())
	tableName := fmt.Sprintf("mssqlAe%d", r.Int64())
	keyBytes := make([]byte, 32)
	_, _ = rand.Read(keyBytes)
	encryptedCek := localcert.WindowsCertificateStoreKeyProvider.EncryptColumnEncryptionKey(certPath, KeyEncryptionAlgorithm, keyBytes)
	createCek := fmt.Sprintf(createColumnEncryptionKey, cekName, certPath, encryptedCek)
	_, err = conn.Exec(createCek)
	if err != nil {
		t.Fatalf("Unable to create CEK: %s", err.Error())
	}
	defer conn.Exec(fmt.Sprintf(dropColumnEncryptionKey, cekName))
	_, _ = conn.Exec("DROP TABLE IF EXISTS " + tableName)
	_, err = conn.Exec(fmt.Sprintf(createEncryptedTable, tableName, cekName, cekName))
	if err != nil {
		t.Fatalf("Failed to create encrypted table %s", err.Error())
	}
	defer conn.Exec("DROP TABLE IF EXISTS " + tableName)
	_, err = conn.Exec("INSERT INTO "+tableName+" VALUES (@p1, @p2)", int32(1), NChar("mycol2"))
	if err != nil {
		t.Logf("Failed to insert row in encrypted table %s", err.Error())
	}
	rows, err := conn.Query("select top (1) col1, col2 from " + tableName)
	if err != nil {
		t.Fatalf("Unable to query encrypted columns: %v", err.(Error).All)
	}
	if !rows.Next() {
		rows.Close()
		t.Fatalf("rows.Next returned false")
	}
	cols, err := rows.ColumnTypes()
	if err != nil {
		t.Fatalf("rows.ColumnTypes failed %s", err.Error())
	}
	if cols[0].DatabaseTypeName() != "INT" {
		t.Fatalf("Got wrong type name for intcol %s", cols[0].DatabaseTypeName())
	}
	var col1 int32
	var col2 string
	err = rows.Scan(&col1, &col2)
	if err != nil {
		rows.Close()
		t.Fatalf("rows.Scan failed: %s", err.Error())
	}
	if col1 != 1 || col2 != "mycol2" {
		rows.Close()
		t.Fatalf("Got incorrect scan values %d and %s", col1, col2)
	}
	rows.Close()
	err = rows.Err()
	if err != nil {
		t.Fatalf("rows.Err() has non-nil value: %s", err.Error())
	}
}

const (
	createColumnMasterKey     = `CREATE COLUMN MASTER KEY [%s] WITH (KEY_STORE_PROVIDER_NAME= 'MSSQL_CERTIFICATE_STORE', KEY_PATH='%s')`
	dropColumnMasterKey       = `DROP COLUMN MASTER KEY [%s]`
	createColumnEncryptionKey = `CREATE COLUMN ENCRYPTION KEY [%s] WITH VALUES (COLUMN_MASTER_KEY = [%s], ALGORITHM = 'RSA_OAEP', ENCRYPTED_VALUE = 0x%x )`
	dropColumnEncryptionKey   = `DROP COLUMN ENCRYPTION KEY [%s]`
	createEncryptedTable      = `CREATE TABLE %s 
	    (col1 int 
			ENCRYPTED WITH (ENCRYPTION_TYPE = DETERMINISTIC,
							ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256',
							COLUMN_ENCRYPTION_KEY = [%s]),
		col2 nchar(10) COLLATE Latin1_General_BIN2
			ENCRYPTED WITH (ENCRYPTION_TYPE = DETERMINISTIC,
				ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256',
				COLUMN_ENCRYPTION_KEY = [%s])
		)`
)
