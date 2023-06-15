package aecmk

import (
	"fmt"
	"time"
)

const (
	CertificateStoreKeyProvider = "MSSQL_CERTIFICATE_STORE"
	CspKeyProvider              = "MSSQL_CSP_PROVIDER"
	CngKeyProvider              = "MSSQL_CNG_STORE"
	AzureKeyVaultKeyProvider    = "AZURE_KEY_VAULT"
	JavaKeyProvider             = "MSSQL_JAVA_KEYSTORE"
)

// ColumnEncryptionKeyLifetime is the default lifetime of decrypted Column Encryption Keys in the global cache.
// The default is 2 hours
var ColumnEncryptionKeyLifetime time.Duration = 2 * time.Hour

type CekCacheEntry struct {
	Expiry time.Time
	Key    []byte
}

type CekCache map[string]CekCacheEntry

type CekProvider struct {
	Provider      ColumnEncryptionKeyProvider
	DecryptedKeys CekCache
}

// no synchronization on this map. Providers register during init.
type ColumnEncryptionKeyProviderMap map[string]*CekProvider

var globalCekProviderFactoryMap = ColumnEncryptionKeyProviderMap{}

// ColumnEncryptionKeyProvider is the interface for decrypting and encrypting column encryption keys.
// It is similar to .Net https://learn.microsoft.com/dotnet/api/microsoft.data.sqlclient.sqlcolumnencryptionkeystoreprovider.
type ColumnEncryptionKeyProvider interface {
	// DecryptColumnEncryptionKey decrypts the specified encrypted value of a column encryption key.
	// The encrypted value is expected to be encrypted using the column master key with the specified key path and using the specified algorithm.
	DecryptColumnEncryptionKey(masterKeyPath string, encryptionAlgorithm string, encryptedCek []byte) []byte
	// EncryptColumnEncryptionKey encrypts a column encryption key using the column master key with the specified key path and using the specified algorithm.
	EncryptColumnEncryptionKey(masterKeyPath string, encryptionAlgorithm string, cek []byte) []byte
	// SignColumnMasterKeyMetadata digitally signs the column master key metadata with the column master key
	// referenced by the masterKeyPath parameter. The input values used to generate the signature should be the
	// specified values of the masterKeyPath and allowEnclaveComputations parameters. May return an empty slice if not supported.
	SignColumnMasterKeyMetadata(masterKeyPath string, allowEnclaveComputations bool) []byte
	// VerifyColumnMasterKeyMetadata verifies the specified signature is valid for the column master key
	// with the specified key path and the specified enclave behavior. Return nil if not supported.
	VerifyColumnMasterKeyMetadata(masterKeyPath string, allowEnclaveComputations bool) *bool
	// KeyLifetime is an optional Duration. Keys fetched by this provider will be discarded after their lifetime expires.
	// If it returns nil, the keys will expire based on the value of ColumnEncryptionKeyLifetime.
	// If it returns zero, the keys will not be cached.
	KeyLifetime() *time.Duration
}

func RegisterCekProvider(name string, provider ColumnEncryptionKeyProvider) error {
	_, ok := globalCekProviderFactoryMap[name]
	if ok {
		return fmt.Errorf("CEK provider %s is already registered", name)
	}
	globalCekProviderFactoryMap[name] = &CekProvider{Provider: provider, DecryptedKeys: CekCache{}}
	return nil
}

func GetGlobalCekProviders() (providers ColumnEncryptionKeyProviderMap) {
	providers = make(ColumnEncryptionKeyProviderMap)
	for i, p := range globalCekProviderFactoryMap {
		providers[i] = p
	}
	return
}
