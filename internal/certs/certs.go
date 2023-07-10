package certs

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"github.com/Microsoft/go-winio/pkg/guid"
)

// TODO: Create a Linux equivalent.
const (
	createUserCertScript = `New-SelfSignedCertificate -Subject "%s" -CertStoreLocation Cert:CurrentUser\My -KeyExportPolicy Exportable -Type DocumentEncryptionCert -KeyUsage KeyEncipherment -Keyspec KeyExchange -KeyLength 2048 -HashAlgorithm 'SHA256' | select {$_.Thumbprint}`
	deleteUserCertScript = `Get-ChildItem Cert:\CurrentUser\My\%s | Remove-Item -DeleteKey`
)

func ProvisionMasterKeyInCertStore() (thumbprint string, err error) {
	var g guid.GUID
	if g, err = guid.NewV4(); err != nil {
		return
	}
	subject := fmt.Sprintf(`gomssqltest-%s`, g.String())

	cmd := exec.Command(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `/ExecutionPolicy`, `Unrestricted`, fmt.Sprintf(createUserCertScript, subject))
	buf := &memoryBuffer{buf: new(bytes.Buffer)}
	cmd.Stdout = buf
	if err = cmd.Run(); err != nil {
		err = fmt.Errorf("Unable to create cert for encryption: %v", err.Error())
		return
	}
	out := buf.buf.String()
	thumbprint = strings.Trim(out[strings.LastIndex(out, "-")+1:], " \r\n")
	return
}

func DeleteMasterKeyCert(thumbprint string) error {
	cmd := exec.Command(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `/ExecutionPolicy`, `Unrestricted`, fmt.Sprintf(deleteUserCertScript, thumbprint))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Unable to delete user cert %s. %s", thumbprint, err.Error())
	}
	return nil
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
