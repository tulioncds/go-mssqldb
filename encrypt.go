package mssql

import (
	"context"
	"strings"
)

// when Always Encrypted is turned on, we have to ask the server for metadata about how to encrypt input parameters.
func (s *Stmt) encryptArgs(ctx context.Context, args []namedValue) (encryptedArgs []namedValue, err error) {
	// q := Stmt{c:s.c,
	// 	paramCount:s.paramCount,
	// 	query: "sp_describe_parameter_encryption",
	// }
	return args, nil
}

func prepareEncryptionQuery(isProc bool, q string, args []namedValue) (query string, err error) {
	return "", nil
}

// Based on the .Net implementation at https://github.com/dotnet/SqlClient/blob/2b31810ce69b88d707450e2059ee8fbde63f774f/src/Microsoft.Data.SqlClient/netcore/src/Microsoft/Data/SqlClient/SqlCommand.cs#L6040
func buildStoredProcedureStatementForColumnEncryption(sproc string, args []namedValue) string {
	b := new(strings.Builder)
	_, _ = b.WriteString("EXEC ")
	q := TSQLQuoter{}
	sproc = q.ID(sproc)

	b.WriteString(sproc)

	// Unlike ADO.Net, go-mssqldb doesn't support ReturnValue named parameters
	first := true
	for _, a := range args {
		if !first {
			b.WriteRune(',')
		}
		first = false
		b.WriteRune(' ')
		appendPrefixedParameterName(b, a.Name)
		b.WriteRune('=')
		appendPrefixedParameterName(b, a.Name)
		if isOutputValue(a.Value) {
			b.WriteString(" OUTPUT")
		}
	}
	return b.String()
}

func appendPrefixedParameterName(b *strings.Builder, p string) {
	if len(p) > 0 {
		if p[0] != '@' {
			b.WriteRune('@')
		}
		b.WriteString(p)
	}
}
