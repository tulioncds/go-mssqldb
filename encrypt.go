package mssql

import (
	"context"
	"database/sql/driver"
	"fmt"
	"io"
	"strings"
)

type ColumnEncryptionType int

var (
	ColumnEncryptionPlainText     ColumnEncryptionType = 0
	ColumnEncryptionDeterministic ColumnEncryptionType = 1
	ColumnEncryptionRandomized    ColumnEncryptionType = 1
)

type cekData struct {
	ordinal         int
	database_id     int
	id              int
	version         int
	metadataVersion []byte
	encryptedValue  []byte
	cmkStoreName    string
	cmkPath         string
	algorithm       string
	byEnclave       bool
	cmkSignature    string
}

type parameterEncData struct {
	ordinal     int
	name        string
	algorithm   int
	encType     ColumnEncryptionType
	cekOrdinal  int
	ruleVersion int
}

// when Always Encrypted is turned on, we have to ask the server for metadata about how to encrypt input parameters.
func (s *Stmt) encryptArgs(ctx context.Context, args []namedValue) (encryptedArgs []namedValue, err error) {
	q := Stmt{c: s.c,
		paramCount: s.paramCount,
		query:      "sp_describe_parameter_encryption",
	}
	newArgs, err := s.prepareEncryptionQuery(isProc(s.query), s.query, args)
	if err != nil {
		return
	}
	rows, err := q.queryContext(ctx, newArgs)
	if err != nil {
		return
	}
	cekInfo, paramsInfo, err := processDescribeParameterEncryption(rows)
	if err != nil {
		return
	}
	fmt.Printf("cekInfo: %v\nparamsInfo:%v\n", cekInfo, paramsInfo)
	return args, nil
}

// returns the arguments to sp_describe_parameter_encryption
// sp_describe_parameter_encryption
// [ @tsql = ] N'Transact-SQL_batch' ,
// [ @params = ] N'parameters'
// [ ;]
func (s *Stmt) prepareEncryptionQuery(isProc bool, q string, args []namedValue) (newArgs []namedValue, err error) {
	if isProc {
		newArgs = make([]namedValue, 1)
		newArgs[0] = namedValue{Name: "tsql", Ordinal: 0, Value: buildStoredProcedureStatementForColumnEncryption(q, args)}
		return
	}
	newArgs = make([]namedValue, 2)
	newArgs[0] = namedValue{Name: "tsql", Ordinal: 0, Value: q}
	params, err := s.buildParametersForColumnEncryption(args)
	if err != nil {
		return
	}
	newArgs[1] = namedValue{Name: "params", Ordinal: 1, Value: params}
	return
}

func (s *Stmt) buildParametersForColumnEncryption(args []namedValue) (parameters string, err error) {
	_, decls, err := s.makeRPCParams(args, false)
	if err != nil {
		return
	}
	parameters = strings.Join(decls, ", ")
	return
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

func processDescribeParameterEncryption(rows driver.Rows) (cekInfo []cekData, paramInfo []parameterEncData, err error) {
	cekInfo = make([]cekData, 0)
	values := make([]driver.Value, 9)
	qerr := rows.Next(values)
	for qerr == nil {
		cekInfo = append(cekInfo, cekData{ordinal: int(values[0].(int64)),
			database_id:     int(values[1].(int64)),
			id:              int(values[2].(int64)),
			version:         int(values[3].(int64)),
			metadataVersion: values[4].([]byte),
			encryptedValue:  values[5].([]byte),
			cmkStoreName:    values[6].(string),
			cmkPath:         values[7].(string),
			algorithm:       values[8].(string),
		})
		qerr = rows.Next(values)
	}
	if len(cekInfo) == 0 || qerr != io.EOF {
		if qerr != io.EOF {
			err = qerr
		} else {
			err = fmt.Errorf("No column encryption key rows were returned from sp_describe_parameter_encryption")
		}
		return
	}
	r := rows.(driver.RowsNextResultSet)
	err = r.NextResultSet()
	if err != nil {
		return
	}
	paramInfo = make([]parameterEncData, 0)
	qerr = rows.Next(values[:6])
	for qerr == nil {
		paramInfo = append(paramInfo, parameterEncData{ordinal: int(values[0].(int64)),
			name:        values[1].(string),
			algorithm:   int(values[2].(int64)),
			encType:     ColumnEncryptionType(values[3].(int64)),
			cekOrdinal:  int(values[4].(int64)),
			ruleVersion: int(values[5].(int64)),
		})
		qerr = rows.Next(values[:6])
	}
	if len(paramInfo) == 0 || qerr != io.EOF {
		if qerr != io.EOF {
			err = qerr
		} else {
			err = fmt.Errorf("No parameter encryption rows were returned from sp_describe_parameter_encryption")
		}
	}
	return
}
