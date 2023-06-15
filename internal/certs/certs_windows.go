package certs

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"unsafe"

	"golang.org/x/sys/windows"
)

func FindCertBySignatureHash(storeHandle windows.Handle, hash []byte) (interface{}, *x509.Certificate) {
	var certContext *windows.CertContext
	var err error
	cryptoAPIBlob := windows.CryptHashBlob{
		Size: uint32(len(hash)),
		Data: &hash[0],
	}

	certContext, err = windows.CertFindCertificateInStore(
		storeHandle,
		windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
		0,
		windows.CERT_FIND_HASH,
		unsafe.Pointer(&cryptoAPIBlob),
		nil)

	if err != nil {

		panic(fmt.Errorf("Unable to find certificate by signature hash. %s", err.Error()))
	}
	pk, cert, err := certContextToX509(certContext)
	if err != nil {
		panic(err)
	}

	return pk, cert
}

func certContextToX509(ctx *windows.CertContext) (pk interface{}, cert *x509.Certificate, err error) {
	// To ensure we don't mess with the cert context's memory, use a copy of it.
	src := (*[1 << 20]byte)(unsafe.Pointer(ctx.EncodedCert))[:ctx.Length:ctx.Length]
	der := make([]byte, int(ctx.Length))
	copy(der, src)

	cert, err = x509.ParseCertificate(der)
	if err != nil {
		return
	}
	var kh windows.Handle
	var keySpec uint32
	var freeProvOrKey bool
	err = windows.CryptAcquireCertificatePrivateKey(ctx, windows.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, nil, &kh, &keySpec, &freeProvOrKey)
	if err != nil {
		return
	}

	pkBytes, err := nCryptExportKey(kh, "RSAFULLPRIVATEBLOB")
	if freeProvOrKey {
		_, _, _ = procNCryptFreeObject.Call(uintptr(kh))
	}
	if err != nil {
		return
	}

	pk, err = unmarshalRSA(pkBytes)
	return
}

var (
	nCrypt               = windows.MustLoadDLL("ncrypt.dll")
	procNCryptExportKey  = nCrypt.MustFindProc("NCryptExportKey")
	procNCryptFreeObject = nCrypt.MustFindProc("NCryptFreeObject")
)

// wide returns a pointer to a uint16 representing the equivalent
// to a Windows LPCWSTR.
func wide(s string) *uint16 {
	w, _ := windows.UTF16PtrFromString(s)
	return w
}

func nCryptExportKey(kh windows.Handle, blobType string) ([]byte, error) {
	var size uint32
	// When obtaining the size of a public key, most parameters are not required
	r, _, err := procNCryptExportKey.Call(
		uintptr(kh),
		0,
		uintptr(unsafe.Pointer(wide(blobType))),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		0)
	if !errors.Is(err, windows.Errno(0)) {
		return nil, fmt.Errorf("nCryptExportKey returned %w", err)
	}
	if r != 0 {
		return nil, fmt.Errorf("NCryptExportKey returned 0x%X during size check", uint32(r))
	}

	// Place the exported key in buf now that we know the size required
	buf := make([]byte, size)
	r, _, err = procNCryptExportKey.Call(
		uintptr(kh),
		0,
		uintptr(unsafe.Pointer(wide(blobType))),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		0)
	if !errors.Is(err, windows.Errno(0)) {
		return nil, fmt.Errorf("nCryptExportKey returned %w", err)
	}
	if r != 0 {
		return nil, fmt.Errorf("NCryptExportKey returned 0x%X during export", uint32(r))
	}
	return buf, nil
}

// TODO: See if we can rewrite this to avoid copying the data from buf twice per field
func unmarshalRSA(buf []byte) (*rsa.PrivateKey, error) {
	// BCRYPT_RSA_BLOB -- https://learn.microsoft.com/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
	header := struct {
		Magic         uint32
		BitLength     uint32
		PublicExpSize uint32
		ModulusSize   uint32
		Prime1Size    uint32
		Prime2Size    uint32
	}{}

	r := bytes.NewReader(buf)
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return nil, err
	}

	if header.Magic != 0x33415352 { // "RSA3" BCRYPT_RSAFULLPRIVATE_MAGIC
		return nil, fmt.Errorf("invalid header magic %x", header.Magic)
	}

	if header.PublicExpSize > 8 {
		return nil, fmt.Errorf("unsupported public exponent size (%d bits)", header.PublicExpSize*8)
	}

	// the exponent is in BigEndian format, so read the data into the right place in the buffer
	exp := make([]byte, 8)
	n, err := r.Read(exp[8-header.PublicExpSize:])

	if err != nil {
		return nil, fmt.Errorf("failed to read public exponent %w", err)
	}

	if n != int(header.PublicExpSize) {
		return nil, fmt.Errorf("failed to read correct public exponent size, read %d expected %d", n, int(header.PublicExpSize))
	}

	mod := make([]byte, header.ModulusSize)
	n, err = r.Read(mod)

	if err != nil {
		return nil, fmt.Errorf("failed to read modulus %w", err)
	}

	if n != int(header.ModulusSize) {
		return nil, fmt.Errorf("failed to read correct modulus size, read %d expected %d", n, int(header.ModulusSize))
	}

	pk := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: new(big.Int).SetBytes(mod),
			E: int(binary.BigEndian.Uint64(exp)),
		},
		D:      new(big.Int),
		Primes: make([]*big.Int, 2),
	}
	prime := make([]byte, header.Prime1Size)
	n, err = r.Read(prime)
	if err != nil {
		return nil, fmt.Errorf("failed to read prime1 %w", err)
	}
	pk.Primes[0] = new(big.Int).SetBytes(prime)
	prime = make([]byte, header.Prime2Size)
	n, err = r.Read(prime)
	if err != nil {
		return nil, fmt.Errorf("failed to read prime2 %w", err)
	}
	pk.Primes[1] = new(big.Int).SetBytes(prime)
	expBytes := make([]byte, 2*header.Prime1Size+header.Prime2Size+header.ModulusSize)
	n, err = r.Read(expBytes)
	if err != nil {
		return nil, fmt.Errorf("Unable to read PrivateExponent %w", err)
	}
	pk.D = new(big.Int).SetBytes(expBytes[2*header.Prime1Size+header.Prime2Size:])
	return pk, nil
}
